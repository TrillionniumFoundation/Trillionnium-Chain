import ast,datetime,hashlib,importlib.metadata,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-final-business-20261107")
OUT=pathlib.Path("/home/qian-qi/throughput-ci-observation-20261107/cell-formal-preparation-v1")
OUT.mkdir(exist_ok=False)
SOURCE="9fedf7ecbbe07177069c030592b4e03dcffebb81"
ENV=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1")
records=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(name,args,input=None,required=False):
 start=time.time_ns();p=subprocess.run(args,cwd=ROOT,env=ENV,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
 for suffix,data in (("stdout",p.stdout),("stderr",p.stderr)):(OUT/(name+"."+suffix)).write_bytes(data)
 row={"name":name,"argv":args,"started_ns":start,"ended_ns":time.time_ns(),"exit_code":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr)}
 records.append(row);(OUT/"commands.json").write_text(json.dumps(records,indent=2)+"\n")
 if required and p.returncode:raise RuntimeError(name+" failed: "+str(p.returncode))
 return p
def git(name,*args,required=False,input=None):return run(name,["/usr/bin/git","--no-optional-locks",*args],required=required,input=input)
pre=run("project-preflight",["bash","scripts/project-preflight.sh"],required=True)
head=git("head-before","rev-parse","HEAD",required=True).stdout.decode().strip()
tree=git("tree-before","rev-parse","HEAD^{tree}",required=True).stdout.decode().strip()
status=git("status-before","status","--porcelain=v1","--untracked-files=all",required=True).stdout.decode()
selector_path="formal/pon-nakamoto-v1/experiments/model_loop.py"
selector=(ROOT/selector_path).read_bytes()
selector_git=git("selector-head","show",head+":"+selector_path,required=True).stdout
assert selector==selector_git
classes_raw=git("model-contract-head","show",head+":formal/pon-nakamoto-v1/model_contract.py",required=True).stdout
classes_source=classes_raw.decode();classes_lines=[{"line":i+1,"text":l} for i,l in enumerate(classes_source.splitlines()) if "CLASSES" in l or "FAMILY" in l][:16]
fixtures=[]
for name in ("model.json","consumer.json","evaluation-bundle.json"):
 rel="evidence/pon-native-node-v1/model-current/model/"+name;p=ROOT/rel
 b=git("fixture-object-"+name,"show",head+":"+rel)
 entry={"path":rel,"head_blob_read_exit":b.returncode,"worktree_present":p.is_file(),"worktree_symlink":p.is_symlink()}
 if b.returncode==0:entry.update(expected_bytes=len(b.stdout),expected_sha256=sha(b.stdout),expected_git_blob=hashlib.sha1(b"blob "+str(len(b.stdout)).encode()+b"\0"+b.stdout).hexdigest())
 if p.is_file() and not p.is_symlink():
  raw=p.read_bytes();entry.update(actual_bytes=len(raw),actual_sha256=sha(raw),bytes_equal_HEAD=b.returncode==0 and raw==b.stdout)
  if name=="model.json":entry["model_source"]=json.loads(raw)["source"]
 fixtures.append(entry)
hist_commit=git("historical-commit","cat-file","commit",SOURCE)
hist_tree=git("historical-all-trees-and-blobs","ls-tree","-rtz",SOURCE)
hist_inventory=git("historical-inventory","show",SOURCE+":config/portability-inventory-v1.json")
archives=[]
for rel in ("evidence/pon-cell-integration-v1-20261107","evidence/pon-native-cell-v1-20261107","evidence/pon-useful-cell-stateful-v2-20261107"):
 d=ROOT/rel;row={"directory":rel,"files":[]}
 for name in ("ARCHIVE.json","MANIFEST.json","FILES.json","README.md"):
  p=d/name
  if not p.is_file():continue
  data=p.read_bytes();matches=[]
  if name.endswith(".json"):
   try:obj=json.loads(data)
   except ValueError:obj=None
   def walk(v,path=""):
    if isinstance(v,dict):
     for k,x in v.items():
      if isinstance(x,str) and any(s in x.lower() for s in ("object","pack","261","9fedf7")):matches.append({"json_path":path+"/"+str(k),"value":x})
      walk(x,path+"/"+str(k))
    elif isinstance(v,list):
     for i,x in enumerate(v):walk(x,path+"/"+str(i))
   walk(obj)
   if name=="ARCHIVE.json":row["archive_identity"]=obj
  row["files"].append({"path":str(p),"bytes":len(data),"sha256":sha(data),"matches":matches[:100]})
 archive=d/"retained-runs.tar.gz"
 if archive.is_file():row["archive_worktree"]={"path":str(archive),"bytes":archive.stat().st_size}
 archives.append(row)
runtime={"executable":sys.executable,"version":sys.version,"implementation":sys.implementation.name,"optimize":sys.flags.optimize,"numpy":importlib.metadata.version("numpy"),"cryptography":importlib.metadata.version("cryptography")}
result={"schema":"trnm-cell-formal-preparation-inspection-v1","at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"root":str(ROOT),"head":head,"tree":tree,"dirty_porcelain":status,"historical_source":SOURCE,"git_flags":{"GIT_NO_LAZY_FETCH":"1","GIT_NO_REPLACE_OBJECTS":"1"},"preflight_exit":pre.returncode,"runtime":runtime,"selector":{"path":selector_path,"bytes":len(selector),"sha256":sha(selector),"equals_HEAD":True},"class_definition_lines":classes_lines,"fixtures":fixtures,"historical_queries":{"commit_exit":hist_commit.returncode,"tree_exit":hist_tree.returncode,"inventory_exit":hist_inventory.returncode},"archives":archives,"repository_objects_written":False,"proof_or_native_executed":False}
(OUT/"inspection.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result),flush=True)
