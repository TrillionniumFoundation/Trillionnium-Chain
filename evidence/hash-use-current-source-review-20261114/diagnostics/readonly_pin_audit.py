import datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys
sys.dont_write_bytecode=True
W=pathlib.Path("/private/tmp/chain-hash-use-current-binding-20261114")
E=pathlib.Path("/private/tmp/chain-hash-use-current-binding-evidence-20261114")
D=E/"readonly-pin-audit-v1";D.mkdir()
HEAD="7d8d4c59fcd01480a12e1c64835b202079091800"
BASE="dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
LAST="57b069ae1e7ed32ff95e4f2a18a74d5eadcda550"
env=dict(os.environ,PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
def sh(b):return hashlib.sha256(b).hexdigest()
def go(a):
 r=subprocess.run(["/usr/bin/git","-C",str(W),*a],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if r.returncode:raise RuntimeError(str(a)+": "+r.stderr.decode(errors="replace"))
 return r.stdout
def blob(commit,path):
 oid=go(["rev-parse",commit+":"+path]).decode().strip()
 raw=go(["cat-file","blob",oid])
 assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid
 return oid,raw
def put(name,raw):
 p=D/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 return {"path":str(p),"bytes":len(raw),"sha256":sh(raw)}
def dump(name,data):return put(name,(json.dumps(data,indent=2,sort_keys=True)+"\n").encode())
before={"head":go(["rev-parse","HEAD"]).decode().strip(),"tree":go(["rev-parse","HEAD^{tree}"]).decode().strip(),"status":go(["status","--porcelain=v1","--untracked-files=all"]).decode()}
assert before["head"]==HEAD and before["status"]==""
sys.path.insert(0,str(W/"scripts/ci"))
import hash_use_contract as contract
from pq_source_reader import read_regular
mp=contract.DEFAULT_MANIFEST
moid,mraw=blob(HEAD,mp); assert mraw==read_regular(W,mp,contract.MAX_BYTES)
manifest=contract.strict_json(mraw)
assert len(manifest["source_files"])==31 and len(manifest["uses"])==19
semantic={k:v for k,v in manifest.items() if k!="source_files"}
assert contract.sha(contract.canonical(semantic))==contract.REVIEWED_SEMANTICS_SHA256
assert contract.sha(contract.canonical(manifest["source_files"]))==contract.REVIEWED_SOURCE_MAP_SHA256
prior_oid,prior_raw=blob(LAST,mp);assert prior_raw==mraw
for index,start in enumerate(range(0,len(mraw),30000)):put("manifest-part-"+str(index)+".txt",mraw[start:start+30000])
rows=[];changes=[]
for i,(path,pin) in enumerate(manifest["source_files"].items()):
 current_oid,raw=blob(HEAD,path); physical=read_regular(W,path,contract.MAX_SOURCE_BYTES);assert physical==raw
 old_oid,old_raw=blob(LAST,path)
 source_uses=[identity for identity,row in manifest["uses"].items() if path in row["source_paths"]]
 assert source_uses
 _,dcraw=blob(BASE,path)
 row={"path":path,"declared_pin":pin,"declared_uses":source_uses,"last_mapping_commit":LAST,"last_mapping_blob":old_oid,"last_mapping_bytes":len(old_raw),"last_mapping_sha256":sh(old_raw),"declared_pin_matches_last_mapping_commit":pin=={"bytes":len(old_raw),"sha256":sh(old_raw)},"current_commit":HEAD,"current_blob":current_oid,"current_bytes":len(raw),"current_sha256":sh(raw),"current_raw_equals_worktree":True,"current_equals_dc42":raw==dcraw,"current_matches_declared_pin":pin=={"bytes":len(raw),"sha256":sh(raw)}}
 if not row["current_matches_declared_pin"]:
  filename=path.replace("/","--")
  row["full_blob_delta"]=put("changed/"+filename+".patch",go(["diff","--no-ext-diff","--no-textconv","--binary",old_oid,current_oid]))
  row["current_path_history"]=put("changed/"+filename+".history",go(["log","--format=%H %P %s",LAST+".."+HEAD,"--",path]))
  put("changed/"+filename+".before",old_raw);put("changed/"+filename+".current",raw)
  changes.append(path)
 rows.append(row)
summary={"schema":"hash-use-all-31-source-pins-readonly-review-v1","head":HEAD,"source_before":before,"manifest":{"path":mp,"blob":moid,"bytes":len(mraw),"sha256":sh(mraw),"last_mapping_commit":LAST,"last_mapping_blob":prior_oid,"same_raw_as_last_mapping_commit":True},"review_base_revision":manifest["review_base_revision"],"reviewed_semantics_sha256":contract.REVIEWED_SEMANTICS_SHA256,"reviewed_source_map_sha256":contract.REVIEWED_SOURCE_MAP_SHA256,"declared_use_count":len(manifest["uses"]),"declared_source_count":len(rows),"changed_paths":changes,"changed_count":len(changes),"unchanged_count":len(rows)-len(changes),"all_old_pins_match_last_mapping_commit":all(r["declared_pin_matches_last_mapping_commit"] for r in rows),"all_current_equal_dc42":all(r["current_equals_dc42"] for r in rows),"rows":rows,"no_source_edits":True,"no_tests_run":True}
after={"head":go(["rev-parse","HEAD"]).decode().strip(),"tree":go(["rev-parse","HEAD^{tree}"]).decode().strip(),"status":go(["status","--porcelain=v1","--untracked-files=all"]).decode()}
assert before==after;summary["source_after"]=after
meta=dump("all-31-inputs.json",summary)
print(json.dumps({"summary":meta,"changed_count":len(changes),"unchanged_count":len(rows)-len(changes),"changed_paths":changes,"all_old_pins_match_last_mapping_commit":summary["all_old_pins_match_last_mapping_commit"],"all_current_equal_dc42":summary["all_current_equal_dc42"]}),flush=True)
