import os,sys,pathlib,json,hashlib,subprocess
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
O=pathlib.Path("/private/tmp/chain-prci-N2-w1-ci-review-20261114-v1/consumer-context-v1");O.mkdir(mode=0o700)
R={"N2":"096c6b5f9b952c49389fd975515744074ba61317","P2":"1e54c4ff66a92827c83bea8715f59f6b299e98cf"}
env=os.environ.copy();env.update(GIT_OPTIONAL_LOCKS="0",GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0")
def git(args):
 r=subprocess.run(["/usr/bin/git","--no-replace-objects","--git-dir="+G]+args,env=env,capture_output=True,timeout=60);assert r.returncode==0 and len(r.stdout)<2*1024*1024
 return r.stdout
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
wanted={"w1_native_controls.py","w1_native_rosters_v1.json","w1_stage_measure.py","w1_v2_receipt_controls.py","test_w1_stage_measure.py","test_w1_native_controls.py"}
trees={};rows=[]
for rev,commit in R.items():
 listing=git(["ls-tree","-r",commit,"--","scripts","config/pon"])
 save(O/(rev+"-tree-scope.stdout"),listing)
 entries={}
 for line in listing.decode().splitlines():
  left,path=line.split("\t",1);mode,kind,oid=left.split()
  if pathlib.PurePosixPath(path).name in wanted:entries[path]={"mode":mode,"kind":kind,"oid":oid}
 trees[rev]=entries
assert set(trees["N2"])==set(trees["P2"])
for path in sorted(trees["N2"]):
 n,p=trees["N2"][path],trees["P2"][path];raw=git(["cat-file","blob",n["oid"]])
 assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==n["oid"]
 if n["oid"]!=p["oid"]:
  old=git(["cat-file","blob",p["oid"]]);save(O/"P2"/(path.replace("/","--")+".source"),old)
 file=save(O/"N2"/(path.replace("/","--")+".source"),raw)
 rows.append({"repository_path":path,"N2":n,"P2":p,"same_blob_and_mode":n==p,**file})
save(O/"producer.py",sys.argv[1].encode());ip=save(O/"source-index.json",(json.dumps({"commits":R,"files":rows,"readonly":True,"tests_executed":False},indent=2)+"\n").encode())
print(json.dumps({"index":ip,"files":rows}),flush=True)
