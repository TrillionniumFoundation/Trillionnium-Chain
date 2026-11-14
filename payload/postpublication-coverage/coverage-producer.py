import os,sys,json,hashlib,stat,datetime
from pathlib import Path
assert sys.flags.optimize==0
P=json.loads(sys.argv[1])
OUT=Path("/private/tmp/chain-prci-postpublication-evidence-coverage-20261114-v1")
if OUT.exists():raise ValueError("CREATE_ONLY")
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(pin):
 p=Path(pin["path"])
 if not p.is_absolute() or p.resolve(strict=True)!=p:raise ValueError("canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>4*1024*1024:raise ValueError("regular bounded")
  if fp(p.lstat())!=fp(st):raise ValueError("identity before")
  data=b""
  while True:
   b=os.read(fd,65536)
   if not b:break
   data+=b
  if fp(p.lstat())!=fp(st) or fp(os.fstat(fd))!=fp(st):raise ValueError("identity changed")
 finally:os.close(fd)
 actual={"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
 if actual["bytes"]!=pin["bytes"] or ("sha256"in pin and actual["sha256"]!=pin["sha256"]):raise ValueError("pin mismatch "+str(p))
 return data,actual,fp(st)
sources={}
group_rows=[]
for group in P["groups"]:
 root=Path(group["root"])
 actual_names=[]
 for par,ds,ns in os.walk(root,followlinks=False):
  for d in ds:
   if (Path(par)/d).is_symlink():raise ValueError("symlink directory")
  actual_names.extend(str(Path(par)/n) for n in ns)
 if sorted(actual_names)!=sorted(x["path"] for x in group["expected_files"]):raise ValueError("closed group roster changed")
 group_pins=[]
 for f in group["expected_files"]:
  raw,pin,stamp=read(f)
  group_pins.append(pin)
  if pin["path"] in sources:raise ValueError("overlapping group")
  sources[pin["path"]]={"pin":pin,"fingerprint":stamp,"group":str(root),"scope":group["scope"]}
 group_rows.append({"root":str(root),"scope":group["scope"],"count":len(group_pins),"bytes":sum(x["bytes"]for x in group_pins),"files":group_pins})
for f in P["extra"]:
 raw,pin,stamp=read(f)
 if pin["path"] not in sources:sources[pin["path"]]={"pin":pin,"fingerprint":stamp,"group":"explicit-cross-directory-originals","scope":"original_producer_launcher_or_raw_evidence"}
if len(sources)>400 or sum(v["pin"]["bytes"]for v in sources.values())>16*1024*1024:raise ValueError("coverage bound")
def unwrap(v):
 if isinstance(v,dict)and "content"in v:
  return json.loads(next(x["text"]for x in v["content"]if x["type"]=="text"))
 return v
root_container=json.loads(read(P["notes"]["root_history_terminal_pin"])[0])
expected={"history_suffix_tail":(1,295),"history_explicit_tail":(1,291),"history_central_directory":(0,311),"history_selected_members":(0,310)}
checked=[]
for obs in root_container["observations"]:
 if obs["label"] not in expected:continue
 d=unwrap(obs["complete_read_tool_result"]);expected_exit,expected_bytes=expected[obs["label"]]
 b=bytes.fromhex(d["bytes_hex"])
 if not(d["offset"]==0 and d["next_offset"]==d["available_end"]==len(b)==expected_bytes and hashlib.sha256(b).hexdigest()==d["chunk_sha256"] and d["output_complete"]is True and d["status"]["state"]=="exited" and d["status"]["exit_code"]==expected_exit and d["status"]["capture_error"]is None):raise ValueError("root actual terminal proof")
 if d["session_id"]!=unwrap(obs["original_launch_tool_result"])["session_id"]:raise ValueError("root launch identity")
 checked.append({"label":obs["label"],"session_id":d["session_id"],"exit_code":expected_exit,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"actual_complete":True,"source":P["notes"]["root_history_terminal_pin"]})
if {x["label"]for x in checked}!=set(expected):raise ValueError("missing History terminal")
OUT.mkdir()
def js(v):return(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode()
def put(name,b):
 p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 pin={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 read(pin);return pin
attachments=[put("coverage-producer.py",sys.argv[2].encode())]
for name,source in P["cachedProducers"]:
 if not isinstance(source,str):raise ValueError("missing exact cached source")
 attachments.append(put("cached-actual-producers/"+name,source.encode()))
for t in P["terminalGroups"]:
 pos=0;parts=[]
 for d in t["pages"]:
  b=bytes.fromhex(d["bytes_hex"])
  if not(d["offset"]==pos and d["next_offset"]==pos+len(b) and hashlib.sha256(b).hexdigest()==d["chunk_sha256"] and not d["truncated_before_offset"]):raise ValueError("cached page")
  pos=d["next_offset"];parts.append(b)
 last=t["pages"][-1]
 if not(last["output_complete"]is True and last["status"]["state"]=="exited" and last["status"]["exit_code"]==t["expected_exit"] and last["status"]["capture_error"]is None and last["available_end"]==pos and t["launch"]["session_id"]==last["session_id"]):raise ValueError("cached terminal")
 container={"schema":"trnm-actual-pty-pages-v1","session_id":last["session_id"],"archive_path":last["archive_path"],"original_launch_tool_result":t["launch"],"terminal":last,"pages":t["pages"]}
 pin=put("cached-original-terminals/"+t["label"]+".json",js(container));attachments.append(pin)
 logpin=put("cached-original-terminals/"+t["label"]+".log",b"".join(parts));attachments.append(logpin)
 checked.append({"label":t["label"],"session_id":last["session_id"],"exit_code":t["expected_exit"],"bytes":pos,"sha256":logpin["sha256"],"actual_complete":True,"source":pin,"meaning":t["meaning"]})
for path,r in sources.items():
 _,_,stamp=read(r["pin"])
 if stamp!=r["fingerprint"]:raise ValueError("final source identity")
records=[dict(r["pin"],origin=r["pin"]["path"],group=r["group"],evidence_scope=r["scope"])for path,r in sorted(sources.items())]
records.extend(dict(p,origin=p["path"],group="new-cached-provenance-and-coverage-preparation",evidence_scope="actual_cached_provenance_or_preparation_not_new_execution")for p in attachments)
manifest=dict(P["notes"],prepared_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),groups=group_rows,terminal_verifications=checked,files=records,source_file_count=len(sources),source_bytes=sum(r["pin"]["bytes"]for r in sources.values()),attachment_count=len(attachments),attachment_bytes=sum(p["bytes"]for p in attachments),new_archive_or_git_execution=False)
manifestpin=put("coverage-manifest.json",js(manifest))
readme=("This is a closed original-evidence source roster and preparation record, not an archive or publication execution.\n"
"Archive each unique path once, preserving original status and origin. Original ready017 UNKNOWN and History RANGE_UNSUPPORTED/HOLD are mandatory originals.\n"
"Three budget ZIPs are fully verified; native controls never started. History integrity covers only the acquired tail, central directory and six selected members, not the whole ZIP.\n"
"Original ready017/018 cached tool pages and actual budget extraction/source producers are saved here without rerunning them. Four root-owned History actual terminal objects are pinned as a separate source.\n"
"Do not collect any new/active archive execution directory. Final observer, hosted collector, protected merge and cleanup have not executed and cannot be recorded as success.\n"
"The original History outer acquisition owner PTY terminal was not located; exact GET argv/status/raw/producer/launch.json remain preserved. This does not invalidate the original raw job log, and no terminal is synthesized.\n"
"coverage-manifest.json does not include itself, this README or seal-summary.json; archive this completed directory in addition to the unique explicit source rows.\n")
readmepin=put("README.txt",readme.encode())
seal=put("seal-summary.json",js({"schema":"trnm-prci-postpublication-coverage-seal-v1","status":"CLOSED_PREPARATION_ONLY","manifest":manifestpin,"readme":readmepin,"source_files":len(sources),"source_bytes":manifest["source_bytes"],"new_attachments":len(attachments),"attachment_bytes":manifest["attachment_bytes"],"validated_history_terminal_records":4,"cached_actual_terminal_records_saved":len(P["terminalGroups"]),"remaining_auxiliary_provenance_gaps":P["notes"]["unresolved_auxiliary_provenance"],"archive_execution":False}))
print(json.dumps({"status":"CLOSED_PREPARATION_ONLY","manifest":manifestpin,"seal":seal,"source_files":len(sources),"source_bytes":manifest["source_bytes"],"attachments":len(attachments),"attachment_bytes":manifest["attachment_bytes"],"root_History_terminal_verified":True},sort_keys=True),flush=True)
