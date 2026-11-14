import pathlib,os,stat,json,hashlib,zipfile,datetime,re
BASE=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
R=BASE/"final-external-evidence-existing-source-08c9be-v2"
O=pathlib.Path(__file__).parent
HEAD="08c9becab740ab2c375b970f376a7638f44c9e8e";TREE="036868dfcc953b6f5574c627e0027c3d4e2d3523"
DRIVER=BASE/"run_final_rog_external_evidence_existing_source_v2.py"
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sig(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_mode]
def open_abs(p):
 p=pathlib.PurePosixPath(str(p));assert p.is_absolute() and ".." not in p.parts
 d=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in p.parts[1:-1]:
   q=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=q
  fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 return fd
held=[];cache={};rows=[]
def retain(path,archive_path,role,n=None,h=None):
 fd=open_abs(path);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 with os.fdopen(fd,"rb",closefd=False) as f:b=f.read(s.st_size+1)
 assert sig(s)==sig(os.fstat(fd)) and len(b)==s.st_size
 if n is not None:assert len(b)==n,str(path)
 sha=hashlib.sha256(b).hexdigest()
 if h is not None:assert sha==h,str(path)
 held.append((fd,sig(s),str(path)));cache[archive_path]=b
 row={"path":archive_path,"bytes":len(b),"sha256":sha,"origin":{"host":"rog","path":str(path)},"role":role,"source_version":sig(s)}
 rows.append(row);return b
def save(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
def fi(p):
 b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
started=now()
raw=retain(R/"summary.json","original/summary.json","original-execution",17801,"624efff452b6bd0b2c6ebcf9a47abe3216999a7d051d1e7d0fb9e5ea86fb2ca3")
d=json.loads(raw)
assert d["schema"]=="trnm-final-linux-external-evidence-existing-source-v2" and d["head"]==HEAD and d["tree"]==TREE and d["expected_start_head"]==HEAD
assert d["status"]=="passed" and d["lane_exit"]==0 and d["errors"]==[] and d["source_before_after_verified"] is True and d["hosted_ci_qualification"] is False
assert d["lane_argv"]==["bash","scripts/ci/ci_job.sh","external-evidence-contract"]
assert d["budget"]["local_lane_timeout_seconds"]==2700 and d["budget"]["hosted_job_walltime_equivalence_claimed"] is False
assert d["driver"]=={"path":str(DRIVER),"sha256":"d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a"}
assert d["invocation"]=={"argv":[str(DRIVER),"--head",HEAD,"--tree",TREE,"--evidence-dir",str(R)],"executable":str(BASE/"final-python312-env/bin/python"),"optimize":0}
labels=["initial-head","initial-tree","initial-status","preflight-audit","rust-version","cargo-version","conformance-environment","runtime-environment","verify-source-before","verify-required-evidence-objects","external-evidence-contract","verify-source-after"]
assert [x["label"] for x in d["steps"]]==labels and all(type(x["exit"]) is int and x["exit"]==0 for x in d["steps"])
by={x["label"]:x for x in d["steps"]}
assert by["external-evidence-contract"]["argv"]==d["lane_argv"] and by["external-evidence-contract"]["timeout_seconds"]==2700 and by["external-evidence-contract"]["elapsed_seconds"]==225.948
names={"summary.json"}
for step in d["steps"]:
 for kind in ("stdout","stderr"):
  p=pathlib.Path(step[kind+"_path"]);assert p.parent==R and p.name not in names and p.name==step["label"]+"."+kind
  names.add(p.name);retain(p,"original/"+p.name,"original-execution",step[kind+"_bytes"],step[kind+"_sha256"])
for n in ("source-before.json","source-after.json"):
 names.add(n);retain(R/n,"original/"+n,"original-execution",423,"cd05f60f8bc294b15bddd498b0e7a9ed5d52913d5ef8ec5e92117dea0ddeffda")
actual=set();empty_dirs=[]
for b,ds,fs in os.walk(R,followlinks=False):
 for n in ds:
  p=pathlib.Path(b)/n;assert not p.is_symlink()
  if not any(p.iterdir()):empty_dirs.append(str(p.relative_to(R)))
 for n in fs:
  p=pathlib.Path(b)/n;actual.add(str(p.relative_to(R)))
assert actual==names and len(names)==27,{"unexpected":sorted(actual-names),"missing":sorted(names-actual)}
assert len(rows)==27 and sum(x["bytes"] for x in rows)==112325
before=cache["original/source-before.json"];assert before==cache["original/source-after.json"]
source=json.loads(before);assert source["tested_commit"]==HEAD and source["tested_tree"]==TREE and source["tracked_worktree_verified"] is True and source["kind"]=="head"
assert cache["original/initial-head.stdout"].decode().strip()==HEAD and cache["original/initial-tree.stdout"].decode().strip()==TREE and cache["original/initial-status.stdout"]==b""
check=json.loads(cache["original/verify-required-evidence-objects.stdout"]);expected=json.loads(by["verify-required-evidence-objects"]["argv"][-1])
assert check["fetch_attempted"] is False and len(expected)==14 and check["verified_object_trees"]==expected
lane_first=json.loads(cache["original/external-evidence-contract.stdout"].decode().splitlines()[0])
assert lane_first["verified_object_trees"]==expected and lane_first["fetched"]==[] and lane_first["branch_refs_changed"] is False and lane_first["acceptance_granted"] is False
err=cache["original/external-evidence-contract.stderr"].decode()
assert re.search(r"(?m)^Ran 77 tests in 36\.691s\r?\n\r?\nOK\r?$",err)
retain(DRIVER,"driver/"+DRIVER.name,"original-driver",16404,"d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a")
retain(pathlib.Path(__file__),"producer/"+pathlib.Path(__file__).name,"packaging-producer")
assert len(rows)==29
index={"schema":"trnm-M5-original-external-evidence-package-index-v2","source_head":HEAD,"source_tree":TREE,"original_lane":"external-evidence-contract","original_result":"passed","original_elapsed_seconds":225.948,"original_file_count":27,"original_bytes":112325,"driver":d["driver"],"original_invocation":d["invocation"],"original_lane_argv":d["lane_argv"],"original_step_invocations":[{k:x[k] for k in ("label","argv","cwd","exit","timeout_seconds","elapsed_seconds")} for x in d["steps"]],"source_before_after_equal":True,"required_object_tree_map":expected,"lane_fetched":[],"hosted_ci_qualification":False,"future_M6_qualification":False,"repository_truth_pass_claimed":False,"files":rows,"empty_directories_without_files":sorted(empty_dirs),"unexpected_nested_files_excluded":[]}
ib=(json.dumps(index,indent=2)+"\n").encode();ip=O/"EVIDENCE_INDEX.json";save(ip,ib)
zp=O/"original-external-evidence-08c9be-v2.zip"
with zipfile.ZipFile(zp,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for row in rows:z.writestr(row["path"],cache[row["path"]])
 z.writestr("EVIDENCE_INDEX.json",ib)
verified=[]
with zipfile.ZipFile(zp,"r") as z:
 zs=z.infolist();assert len(zs)==30 and {x.filename for x in zs}==set(cache)|{"EVIDENCE_INDEX.json"}
 bypath={x["path"]:x for x in rows}
 for x in zs:
  b=z.read(x)
  if x.filename=="EVIDENCE_INDEX.json":assert b==ib
  else:
   e=bypath[x.filename];assert len(b)==e["bytes"] and hashlib.sha256(b).hexdigest()==e["sha256"]
  verified.append({"path":x.filename,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"crc32":format(x.CRC,"08x")})
for fd,version,p in held:assert sig(os.fstat(fd))==version,p
summary={"schema":"trnm-M5-original-external-evidence-package-completion-v2","started_at":started,"finished_at":now(),"original_head":HEAD,"original_tree":TREE,"original_result":"passed","original_lane_argv":d["lane_argv"],"original_driver_invocation":d["invocation"],"original_all_12_steps_exit0":True,"original_lane_elapsed_seconds":225.948,"original_file_count":27,"original_bytes":112325,"payload_file_count":29,"zip_member_count":30,"zip":fi(zp),"index":fi(ip),"producer":fi(pathlib.Path(__file__)),"all_member_crc_size_sha_verified":True,"original_source_file_versions_unchanged":True,"source_before_after_equal":True,"verified_object_trees":expected,"fetched":[],"original_readiness_suite":{"tests":77,"elapsed_seconds":36.691,"result":"OK","stderr_member":"original/external-evidence-contract.stderr","scope":"original readiness suite within the completed external lane; not all lane test methods"},"hosted_ci_qualification":False,"future_M6_qualification":False,"repository_truth_pass_claimed":False,"tests_rerun":False,"source_or_git_objects_modified":False,"network_actions_by_packager":False,"unexpected_nested_files_excluded":[]}
sp=O/"package-summary.json";save(sp,(json.dumps(summary,indent=2)+"\n").encode())
for fd,_,_ in held:os.close(fd)
print(json.dumps({"summary":fi(sp),"zip":summary["zip"],"index":summary["index"],"producer":summary["producer"],"original_files":27,"original_bytes":112325,"zip_members":30,"all_crc_sha_verified":True,"source_head":HEAD,"source_tree":TREE,"original_result":"passed","tests_rerun":False,"source_or_git_objects_modified":False}),flush=True)
