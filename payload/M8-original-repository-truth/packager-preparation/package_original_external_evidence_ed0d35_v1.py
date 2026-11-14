import pathlib,os,stat,json,hashlib,zipfile,datetime,re,argparse,math,sys
BASE=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
R=BASE/"final-external-evidence-existing-source-ed0d35-v2"
O=BASE/"package-original-external-evidence-ed0d35-v1-prci"
HEAD="ed0d35487f2a67239e4d646fd41c2c7acb5cc740";TREE="1aa9c21812489080980bdc3c1c2bb43611e88354"
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
 assert archive_path not in cache and re.fullmatch(r"[A-Za-z0-9._/-]+",archive_path) and ".." not in pathlib.PurePosixPath(archive_path).parts
 fd=open_abs(path);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=16*1024*1024
 with os.fdopen(fd,"rb",closefd=False) as f:b=f.read(s.st_size+1)
 assert sig(s)==sig(os.fstat(fd)) and len(b)==s.st_size
 if n is not None:assert len(b)==n,str(path)
 sha=hashlib.sha256(b).hexdigest()
 if h is not None:assert sha==h,str(path)
 held.append((fd,sig(s),str(path)));cache[archive_path]=b
 assert sum(len(v)for v in cache.values())<=32*1024*1024
 row={"path":archive_path,"bytes":len(b),"sha256":sha,"origin":{"host":"rog","path":str(path)},"role":role,"source_version":sig(s)}
 rows.append(row);return b
def save(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
def fi(p):
 b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
assert not sys.flags.optimize
parser=argparse.ArgumentParser(description="Package only a closed, operator-pinned M8 external lane.")
parser.add_argument("--terminal-summary-sha256",required=True)
parser.add_argument("--terminal-exit-code",type=int,choices=(0,1),required=True)
parser.add_argument("--closed-log-manifest-sha256",required=True)
args=parser.parse_args()
assert re.fullmatch(r"[0-9a-f]{64}",args.terminal_summary_sha256)
assert re.fullmatch(r"[0-9a-f]{64}",args.closed_log_manifest_sha256)
assert pathlib.Path(__file__).resolve(strict=True).parent==O and O.resolve(strict=True)==O
assert set(p.name for p in O.iterdir())=={pathlib.Path(__file__).name,"closed-original-logs.json"}
started=now()
manifest_raw=retain(O/"closed-original-logs.json","metadata/closed-original-logs.json",
 "operator-pinned-closed-log-manifest",h=args.closed_log_manifest_sha256)
assert len(manifest_raw)<=256*1024
manifest=json.loads(manifest_raw)
assert isinstance(manifest,dict) and set(manifest)=={"schema","head","tree","receipt_directory","terminal_summary_sha256","files"}
assert manifest["schema"]=="trnm-closed-original-sublogs-manifest-v1" and manifest["head"]==HEAD and manifest["tree"]==TREE
assert manifest["receipt_directory"]==str(R) and manifest["terminal_summary_sha256"]==args.terminal_summary_sha256
assert isinstance(manifest["files"],list) and len(manifest["files"])<=256
nested=[];nested_names=set()
for row in manifest["files"]:
 assert isinstance(row,dict) and set(row)=={"path","bytes","sha256"}
 name=row["path"]
 assert type(name) is str and name.startswith("ci-observations/") and re.fullmatch(r"[A-Za-z0-9._/-]+",name)
 assert str(pathlib.PurePosixPath(name))==name and not pathlib.PurePosixPath(name).is_absolute() and ".." not in pathlib.PurePosixPath(name).parts
 assert name not in nested_names and type(row["bytes"]) is int and 0<=row["bytes"]<=16*1024*1024
 assert type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"])
 nested_names.add(name);nested.append((name,row["bytes"],row["sha256"]))
assert [x[0]for x in nested]==sorted(nested_names) and sum(x[1]for x in nested)<=32*1024*1024
raw=retain(R/"summary.json","original/summary.json","original-execution",h=args.terminal_summary_sha256)
d=json.loads(raw)
assert d["schema"]=="trnm-final-linux-external-evidence-existing-source-v2" and d["head"]==HEAD and d["tree"]==TREE and d["expected_start_head"]==HEAD
assert d["status"] in ("passed","failed") and type(d["lane_exit"]) is int and isinstance(d["errors"],list) and all(type(x)is str for x in d["errors"])
assert d["source_before_after_verified"] is True and d["hosted_ci_qualification"] is False
assert isinstance(d["finished_at"],str) and datetime.datetime.fromisoformat(d["finished_at"]).tzinfo is not None
assert datetime.datetime.fromisoformat(d["finished_at"])>=datetime.datetime.fromisoformat(d["started_at"])
assert d["lane_argv"]==["bash","scripts/ci/ci_job.sh","external-evidence-contract"]
assert d["budget"]["local_lane_timeout_seconds"]==2700 and d["budget"]["hosted_job_walltime_equivalence_claimed"] is False
assert d["driver"]=={"path":str(DRIVER),"sha256":"d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a"}
assert d["invocation"]=={"argv":[str(DRIVER),"--head",HEAD,"--tree",TREE,"--evidence-dir",str(R)],"executable":str(BASE/"final-python312-env/bin/python"),"optimize":0}
labels=["initial-head","initial-tree","initial-status","preflight-audit","rust-version","cargo-version","conformance-environment","runtime-environment","verify-source-before","verify-required-evidence-objects","external-evidence-contract","verify-source-after"]
assert [x["label"] for x in d["steps"]]==labels and all(type(x["exit"]) is int for x in d["steps"])
assert all(x["exit"]==0 for x in d["steps"] if x["label"]!="external-evidence-contract")
by={x["label"]:x for x in d["steps"]}
lane=by["external-evidence-contract"]
assert lane["argv"]==d["lane_argv"] and lane["timeout_seconds"]==2700 and lane["exit"]==d["lane_exit"]
assert type(lane["elapsed_seconds"]) in (int,float) and math.isfinite(lane["elapsed_seconds"]) and lane["elapsed_seconds"]>=0
derived="passed" if lane["exit"]==0 and not d["errors"] else "failed"
assert d["status"]==derived and args.terminal_exit_code==(0 if derived=="passed" else 1)
names={"summary.json"}
for step in d["steps"]:
 for kind in ("stdout","stderr"):
  p=pathlib.Path(step[kind+"_path"]);assert p.parent==R and p.name not in names and p.name==step["label"]+"."+kind
  names.add(p.name);retain(p,"original/"+p.name,"original-execution",step[kind+"_bytes"],step[kind+"_sha256"])
for n in ("source-before.json","source-after.json"):
 names.add(n);retain(R/n,"original/"+n,"original-execution",423,"a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d")
assert len(names)==27
names.update(x[0]for x in nested)
actual=set();empty_dirs=[];inventory_before={}
for b,ds,fs in os.walk(R,followlinks=False):
 for n in ds:
  p=pathlib.Path(b)/n;assert stat.S_ISDIR(p.lstat().st_mode) and not p.is_symlink()
  if not any(p.iterdir()):empty_dirs.append(str(p.relative_to(R)))
 for n in fs:
  p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
  name=str(p.relative_to(R));actual.add(name);inventory_before[name]=sig(s)
assert actual==names and len(names)==27+len(nested),{"unexpected":sorted(actual-names),"missing":sorted(names-actual)}
for relative,n,h in nested:retain(R/relative,"original/"+relative,"original-execution-sublog",n,h)
original_rows=[x for x in rows if x["role"].startswith("original-execution")]
assert len(original_rows)==27+len(nested)
original_count=len(original_rows);original_bytes=sum(x["bytes"]for x in original_rows)
before=cache["original/source-before.json"];assert before==cache["original/source-after.json"]
source=json.loads(before)
assert source=={"base":None,"candidate":HEAD,"kind":"head","prospective_merge":None,
 "schema":"trnm-ci-source-v1","tested_commit":HEAD,"tested_tree":TREE,
 "tests_executed_by_identity_check":False,"tracked_bytes":3994947385,
 "tracked_entries":41677,"tracked_worktree_verified":True}
assert before==cache["original/verify-source-before.stdout"]==cache["original/verify-source-after.stdout"]
assert cache["original/initial-head.stdout"].decode().strip()==HEAD and cache["original/initial-tree.stdout"].decode().strip()==TREE and cache["original/initial-status.stdout"]==b""
check=json.loads(cache["original/verify-required-evidence-objects.stdout"]);expected=json.loads(by["verify-required-evidence-objects"]["argv"][-1])
assert check["fetch_attempted"] is False and len(expected)==14 and check["verified_object_trees"]==expected
lane_first=json.loads(cache["original/external-evidence-contract.stdout"].decode().splitlines()[0])
assert lane_first["verified_object_trees"]==expected and lane_first["fetched"]==[] and lane_first["branch_refs_changed"] is False and lane_first["acceptance_granted"] is False
err=cache["original/external-evidence-contract.stderr"].decode()
matches=re.findall(r"(?m)^Ran 78 tests in ([0-9]+(?:\.[0-9]+)?)s\r?\n\r?\nOK\r?$",err)
assert len(matches)<=1
if derived=="passed":assert len(matches)==1
readiness_elapsed=float(matches[0]) if matches else None
if readiness_elapsed is not None:assert math.isfinite(readiness_elapsed) and readiness_elapsed>=0
readiness={"tests":78 if matches else None,"elapsed_seconds":readiness_elapsed,"result":"OK" if matches else "not_observed",
 "stderr_member":"original/external-evidence-contract.stderr","scope":"original readiness suite within this external lane; not all lane test methods"}
retain(DRIVER,"driver/"+DRIVER.name,"original-driver",16404,"d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a")
retain(pathlib.Path(__file__),"producer/"+pathlib.Path(__file__).name,"packaging-producer")
assert len(rows)==original_count+3
payload_count=len(rows);member_count=len(rows)+1
index={"schema":"trnm-M8-original-external-evidence-package-index-v1","source_head":HEAD,"source_tree":TREE,"original_lane":"external-evidence-contract","original_result":derived,"original_elapsed_seconds":lane["elapsed_seconds"],"original_file_count":original_count,"required_flat_original_file_count":27,"nested_original_log_count":len(nested),"closed_log_manifest_sha256":args.closed_log_manifest_sha256,"operator_terminal_summary_sha256":args.terminal_summary_sha256,"operator_terminal_exit_code":args.terminal_exit_code,"original_lane_exit":lane["exit"],"original_errors":d["errors"],"original_bytes":original_bytes,"driver":d["driver"],"original_invocation":d["invocation"],"original_lane_argv":d["lane_argv"],"original_step_invocations":[{k:x[k] for k in ("label","argv","cwd","exit","timeout_seconds","elapsed_seconds")} for x in d["steps"]],"source_before_after_equal":True,"required_object_tree_map":expected,"lane_fetched":[],"hosted_ci_qualification":False,"future_revision_qualification":False,"repository_truth_pass_claimed":False,"files":rows,"empty_directories_without_files":sorted(empty_dirs),"unexpected_nested_files_excluded":[]}
ib=(json.dumps(index,indent=2)+"\n").encode();ip=O/"EVIDENCE_INDEX.json";save(ip,ib)
zp=O/"original-external-evidence-ed0d35-v1.zip"
with zipfile.ZipFile(zp,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for row in rows:z.writestr(row["path"],cache[row["path"]])
 z.writestr("EVIDENCE_INDEX.json",ib)
verified=[]
with zipfile.ZipFile(zp,"r") as z:
 zs=z.infolist();assert len(zs)==member_count and {x.filename for x in zs}==set(cache)|{"EVIDENCE_INDEX.json"}
 bypath={x["path"]:x for x in rows}
 for x in zs:
  b=z.read(x)
  if x.filename=="EVIDENCE_INDEX.json":assert b==ib
  else:
   e=bypath[x.filename];assert len(b)==e["bytes"] and hashlib.sha256(b).hexdigest()==e["sha256"]
  verified.append({"path":x.filename,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"crc32":format(x.CRC,"08x")})
for fd,version,p in held:
 assert sig(os.fstat(fd))==version,p
 check_fd=open_abs(p)
 try:assert sig(os.fstat(check_fd))==version,p
 finally:os.close(check_fd)
inventory_after={}
for b,ds,fs in os.walk(R,followlinks=False):
 for n in ds:
  p=pathlib.Path(b)/n;assert stat.S_ISDIR(p.lstat().st_mode) and not p.is_symlink()
 for n in fs:
  p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
  inventory_after[str(p.relative_to(R))]=sig(s)
assert inventory_after==inventory_before
summary={"schema":"trnm-M8-original-external-evidence-package-completion-v1","started_at":started,"finished_at":now(),"original_head":HEAD,"original_tree":TREE,"original_result":derived,"original_lane_argv":d["lane_argv"],"original_driver_invocation":d["invocation"],"original_all_12_steps_exit0":all(x["exit"]==0 for x in d["steps"]),"original_lane_elapsed_seconds":lane["elapsed_seconds"],"original_file_count":original_count,"required_flat_original_file_count":27,"nested_original_log_count":len(nested),"closed_log_manifest_sha256":args.closed_log_manifest_sha256,"operator_terminal_summary_sha256":args.terminal_summary_sha256,"operator_terminal_exit_code":args.terminal_exit_code,"original_lane_exit":lane["exit"],"original_errors":d["errors"],"original_bytes":original_bytes,"payload_file_count":payload_count,"zip_member_count":member_count,"zip":fi(zp),"index":fi(ip),"producer":fi(pathlib.Path(__file__)),"all_member_crc_size_sha_verified":True,"original_source_file_versions_unchanged":True,"source_before_after_equal":True,"verified_object_trees":expected,"fetched":[],"original_readiness_suite":readiness,"hosted_ci_qualification":False,"future_revision_qualification":False,"repository_truth_pass_claimed":False,"tests_rerun":False,"source_or_git_objects_modified":False,"network_actions_by_packager":False,"unexpected_nested_files_excluded":[]}
sp=O/"package-summary.json";save(sp,(json.dumps(summary,indent=2)+"\n").encode())
for fd,_,_ in held:os.close(fd)
print(json.dumps({"summary":fi(sp),"zip":summary["zip"],"index":summary["index"],"producer":summary["producer"],"original_files":original_count,"original_bytes":original_bytes,"zip_members":member_count,"all_crc_sha_verified":True,"source_head":HEAD,"source_tree":TREE,"original_result":derived,"tests_rerun":False,"source_or_git_objects_modified":False}),flush=True)
