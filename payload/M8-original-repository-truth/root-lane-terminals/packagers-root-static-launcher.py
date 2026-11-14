import ast,difflib,hashlib,json,os,pathlib,stat,sys
assert not sys.flags.optimize
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
ev=root/"M8-packager-root-static-review-v1";ev.mkdir(mode=0o700)
with (ev/"producer.py").open("x") as f:f.write(sys.argv[1])
base=pathlib.Path("/private/tmp/chain-prci-M8-original-lane-packagers-preparation-20261114-v1")
pins=[
("/private/tmp/chain-prci-M6-original-repository-truth-preparation-20261114-v2/package_original_repository_truth_2a6206_v2.py",25585,"744d34e71ed6036af795a6971fd1e3d855bebc195f9634dc9cd3509ac8a67c1a"),
(str(base/"package_original_repository_truth_ed0d35_v1.py"),28914,"cef78f3610541a8056b297fd5256a2493227d3aa78cd0d964a92c57c687889d8"),
("/private/tmp/chain-prci-M6-original-external-evidence-preparation-20261114-v1/package_original_external_evidence_2a6206_v2.py",8897,"62f177ea0964b01a87c862fa38bb0ff2d4814e6443963e9ae79f7629e02a895f"),
(str(base/"package_original_external_evidence_ed0d35_v1.py"),14207,"0461689e3f7d576250d26faddb3efd61716cb984469154782088a9fe58d0f10f"),
(str(base/"both-packagers-precise.patch"),38183,"6e5621b6665bd614b9391fcf5d564b99249821b448ca19b3b438a19c69e1a69f")]
def ident(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
raws=[];records=[]
for name,n,sha in pins:
 p=pathlib.Path(name);s=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==n
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  assert ident(os.fstat(f.fileno()))==ident(s);raw=f.read(n+1);assert ident(os.fstat(f.fileno()))==ident(s)
 assert ident(p.lstat())==ident(s) and len(raw)==n and hashlib.sha256(raw).hexdigest()==sha
 raws.append(raw);records.append({"path":name,"bytes":n,"sha256":sha})
actual="".join(difflib.unified_diff(raws[0].decode().splitlines(True),raws[1].decode().splitlines(True),fromfile=pins[0][0],tofile=pins[1][0]))+"".join(difflib.unified_diff(raws[2].decode().splitlines(True),raws[3].decode().splitlines(True),fromfile=pins[2][0],tofile=pins[3][0]))
assert actual.encode()==raws[4],"exact reviewed diff reconstruction differs"
for i in (1,3):ast.parse(raws[i],filename=pins[i][0]);compile(raws[i],pins[i][0],"exec",dont_inherit=True,optimize=0)
result={"schema":"trnm-root-M8-packagers-static-review-v1","status":"STATIC_DIFF_VERIFIED","pins":records,"all_reviewed_diff_bytes_match_actual_sources":True,"compile_only":True,"module_or_helpers_executed":False,"source_or_stage_mutations":False}
b=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode()
with (ev/"summary.json").open("xb") as f:f.write(b)
print(json.dumps({"summary":str(ev/"summary.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"status":result["status"]}),flush=True)
