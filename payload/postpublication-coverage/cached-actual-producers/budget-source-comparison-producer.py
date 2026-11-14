import ast,datetime,difflib,hashlib,json,os,stat,subprocess,sys,tomllib
from pathlib import Path
OUT=Path("/private/tmp/chain-prci-R1-budget-input-identity-source-review-20261114-v1")
GIT="/usr/bin/git"
BARE="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
WT=Path("/private/tmp/chain-consolidation-20261114-mainline")
runnerpath="scripts/ci/run_pon_budget_controls.py"
testpath="scripts/ci/test_pon_budget_controls.py"
workflow=".github/workflows/pon-budget-controls.yml"
specs=json.loads(sys.argv[1])
OUT.mkdir(mode=0o700,exist_ok=False)
(OUT/"git-reads").mkdir()
(OUT/"differences").mkdir()
counter=0;steps=[]
def need(v,c):
 if not v:raise ValueError(c)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(name,raw):
 p=OUT/name
 with p.open("xb")as f:f.write(raw)
 need(p.read_bytes()==raw,"OUTPUT_READBACK")
 return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def sj(name,x):return save(name,(json.dumps(x,indent=2,sort_keys=True)+"\n").encode())
def git(args):
 global counter
 counter+=1;label=f"git-reads/{counter:03d}"
 argv=[GIT,"--git-dir="+BARE,*args];start=now()
 p=subprocess.run(argv,cwd="/private/tmp",stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 rec={"argv":argv,"started_at":start,"finished_at":now(),"exit":p.returncode,"stdout":save(label+".stdout",p.stdout),"stderr":save(label+".stderr",p.stderr)}
 steps.append(rec);need(p.returncode==0,"READONLY_GIT_NONZERO")
 need(len(p.stdout)<=2*1024*1024 and len(p.stderr)<=65536,"GIT_OUTPUT_CAP")
 return p.stdout,rec
blobcache={}
def blob(oid):
 if oid not in blobcache:
  raw,rec=git(["cat-file","blob",oid])
  need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid,"BLOB_CONTENT_ADDRESS")
  blobcache[oid]=(raw,rec["stdout"])
 return blobcache[oid]
def tree_read(commit,paths):
 raw,rec=git(["ls-tree","-z","--full-tree",commit,"--",*paths])
 rows={}
 for entry in raw.split(b"\0"):
  if not entry:continue
  left,name=entry.split(b"\t",1);mode,kind,oid=left.decode().split()
  rel=name.decode();need(rel in paths and kind=="blob"and mode in("100644","100755"),"EXACT_TREE_PATH")
  need(rel not in rows,"DUP_TREE")
  body,pin=blob(oid)
  rows[rel]={"commit":commit,"path":rel,"oid":oid,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"raw":pin}
 need(set(rows)==set(paths),"SOURCE_PATH_MISSING")
 return rows
commit_receipts=[]
for commit in [HEAD,*[s["subject"]for s in specs]]:
 raw,rec=git(["cat-file","commit",commit]);need(hashlib.sha1(b"commit "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==commit,"COMMIT_ADDRESS")
 header=raw.split(b"\n\n",1)[0].decode().splitlines()
 commit_receipts.append({"commit":commit,"tree":[x[5:]for x in header if x.startswith("tree ")][0],"parents":[x[7:]for x in header if x.startswith("parent ")],"raw":rec["stdout"]})
rrows=tree_read(HEAD,[runnerpath,testpath,workflow])
rraw=blob(rrows[runnerpath]["oid"])[0]
need(len(rraw)==47276 and hashlib.sha256(rraw).hexdigest()=="cdf44d64590f0dcacf1eee1198f7b81a0dbc80ef0b1716ccacc62520ef59c629","R1_RUNNER")
need(rraw==(WT/runnerpath).read_bytes(),"CURRENT_RUNNER_NOT_R1")
module=ast.parse(rraw)
constants={n.targets[0].id:ast.literal_eval(n.value)for n in module.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in("COMMON_INPUTS","GROUP_INPUTS")}
common=constants["COMMON_INPUTS"];groups=constants["GROUP_INPUTS"]
allpaths=list(dict.fromkeys([*common,*[p for xs in groups.values()for p in xs]]))
current=tree_read(HEAD,allpaths)
cases=[]
for spec in specs:
 group={"pool-scan-before":"pool-scan","budget-before-v2":"budget","pool-before-v2":"pool"}[spec["component"]]
 paths=[*common,*groups[group]];subject=tree_read(spec["subject"],paths);comp=[]
 for i,path in enumerate(paths):
  a,b=subject[path],current[path];equal=a["oid"]==b["oid"]
  rec={"guard_order":i,"group":"common"if path in common else group,"path":path,"equal":equal,"subject":a,"driver":b}
  if not equal:
   ar,br=blob(a["oid"])[0],blob(b["oid"])[0]
   diff="".join(difflib.unified_diff(ar.decode().splitlines(True),br.decode().splitlines(True),fromfile=spec["subject"]+":"+path,tofile=HEAD+":"+path))
   rec["diff"]=save("differences/"+spec["component"]+"--"+path.replace("/","--")+".patch",diff.encode())
   if path.endswith(".toml"):
    ap,bp=tomllib.loads(ar.decode()),tomllib.loads(br.decode())
    rec["toml_top_level_keys_changed"]=[k for k in sorted(set(ap)|set(bp))if ap.get(k)!=bp.get(k)]
    rec["profile_semantically_equal"]=ap.get("profile")==bp.get("profile")
  comp.append(rec)
 cases.append({"mode":spec["component"],"subject":spec["subject"],"subject_tree":next(x["tree"]for x in commit_receipts if x["commit"]==spec["subject"]),"comparison_order":"common inputs first, then exact selected group","comparisons":comp,"first_actual_mismatch":next((x["path"]for x in comp if not x["equal"]),None)})
result={"schema":"trnm-r1-budget-identity-source-review-v1","observed_at":now(),"current_driver":HEAD,"current_tree":commit_receipts[0]["tree"],"current_runner":rrows[runnerpath],"current_test":rrows[testpath],"current_workflow":rrows[workflow],"guard_line":685,"guard_is_before_compilation":True,"commits":commit_receipts,"cases":cases,"source_git_mutations":False,"target_helpers_or_tests_executed":False,"qualification":False,"steps":steps}
pin=sj("source-comparison.json",result)
print(json.dumps({"receipt":pin,"cases":[{"mode":x["mode"],"first_actual_mismatch":x["first_actual_mismatch"],"inputs":[{"path":y["path"],"equal":y["equal"],"subject_oid":y["subject"]["oid"],"driver_oid":y["driver"]["oid"],"diff":y.get("diff"),"toml_top_level_keys_changed":y.get("toml_top_level_keys_changed"),"profile_semantically_equal":y.get("profile_semantically_equal")}for y in x["comparisons"]]}for x in cases],"runner":rrows[runnerpath],"test":rrows[testpath],"workflow":rrows[workflow]}),flush=True)
