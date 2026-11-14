import os,sys,json,hashlib,subprocess,datetime,concurrent.futures,importlib.util
from pathlib import Path
assert sys.flags.optimize==0
OUT=Path("/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1/workflow-read-v2")
OUT.mkdir(exist_ok=False)
def put(name,raw):
 p=OUT/name
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==raw
 return{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def js(name,x):return put(name,(json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
pp=put("workflow-trigger-inspection-producer.py",sys.argv[1].encode())
G="/usr/bin/git";DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0")
heads={"current":"5df7ae6f482157c5f7fdcbcd52222117a965053f","base":"dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"}
records=[];commands=[]
for label,head in heads.items():
 argv=[G,"--git-dir="+DB,"ls-tree","-r","-z",head,"--",".github/workflows"]
 r=subprocess.run(argv,capture_output=True,timeout=30,env=env)
 commands.append({"argv":argv,"exit":r.returncode,"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest()})
 if r.returncode:raise RuntimeError("local exact workflow listing failed")
 for entry in r.stdout.split(b"\0"):
  if not entry:continue
  meta,name=entry.split(b"\t",1);mode,typ,oid=meta.decode().split();name=name.decode()
  assert typ=="blob"and mode=="100644"and name.startswith(".github/workflows/")
  if not name.endswith((".yml",".yaml")):continue
  records.append({"revision":head,"revision_label":label,"path":name,"oid":oid})
assert len(records)<256
def read_record(row):
 argv=[G,"--git-dir="+DB,"cat-file","blob",row["oid"]]
 r=subprocess.run(argv,capture_output=True,timeout=30,env=env)
 assert r.returncode==0 and len(r.stdout)<256*1024
 b=r.stdout;assert hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==row["oid"]
 text=b.decode();lines=text.splitlines(True);starts=[i for i,x in enumerate(lines)if x.startswith("on:")or x.startswith('"on":')or x.startswith("'on':")]
 assert len(starts)==1,(row["path"],starts)
 st=starts[0];en=st+1
 while en<len(lines)and(not lines[en].strip()or lines[en].startswith((" ","\t","#"))):en+=1
 row={**row,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"on_start_line":st+1,"on_end_line":en,"on_block":"".join(lines[st:en]),"source_lines":len(lines),"read_command":{"argv":argv,"exit":r.returncode}}
 return row,b
with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
 values=list(pool.map(read_record,records))
has_yaml=importlib.util.find_spec("yaml")is not None
if has_yaml:import yaml
out=[]
for index,(row,b)in enumerate(values):
 row["captured_source"]=put("workflow-"+row["revision_label"]+"-"+str(index).zfill(3)+".yml.raw",b)
 if has_yaml:
  obj=yaml.load(b.decode(),Loader=yaml.BaseLoader)
  row["parsed_on"]=obj["on"]
  on=obj["on"]
  if isinstance(on,str):events=[on]
  elif isinstance(on,list):events=on
  else:events=list(on)
  row["pull_request_events"]={e:(on[e]if isinstance(on,dict)else None)for e in events if e in("pull_request","pull_request_target")}
 out.append(row)
summary=js("workflow-trigger-review.json",{"schema":"trnm-H5DF-pr-body-workflow-trigger-source-review-v1","status":"SOURCE_CAPTURED","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"producer":pp,"pure_readonly_git":True,"network_or_helper_execution":False,"parser":"PyYAML BaseLoader"if has_yaml else"literal top-level on blocks only","revisions":heads,"list_commands":commands,"workflow_records":out})
print(json.dumps({"summary":summary,"count":len(out),"parser_available":has_yaml,"on_blocks":[{k:x[k]for k in("revision_label","path","on_start_line","on_end_line","on_block")}for x in out]},sort_keys=True))
