import hashlib,json,os,pathlib,subprocess
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=R/"protocol-source-comparison-v1";D.mkdir(mode=0o700)
DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
REV={"N":"5a4b7fe8de1adce803184f262fd9f704ead1930c","N2":"096c6b5f9b952c49389fd975515744074ba61317","R1":"2a86462a1ab20c68151719ba4635e3c294391e64"}
paths=["scripts/ci/run_from_zero_native.py","scripts/ci/run_from_zero_host.py","scripts/ci/ci_job.sh","trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs","trillionnium/crates/trnm-pon-node/src/store.rs"]
env=os.environ.copy();env.update({"GIT_NO_LAZY_FETCH":"1","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"})
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
def git(args):
 p=subprocess.run(["/usr/bin/git","--no-replace-objects","--git-dir="+DB,*args],cwd="/private/tmp",env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 assert p.returncode==0 and len(p.stdout)<=2097152,(args,p.returncode,p.stderr[:300])
 return p.stdout
rows=[];objects={}
for path in paths:
 row={"path":path,"revisions":{}}
 for label,sha in REV.items():
  oid=git(["rev-parse",sha+":"+path]).decode().strip();data=git(["cat-file","blob",oid])
  row["revisions"][label]={"commit":sha,"git_blob":oid,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
  if path in paths[:3] and oid not in objects:
   name=path.replace("/","--")+"."+oid+".raw"
   with (D/name).open("xb") as f:f.write(data)
   objects[oid]=str(D/name)
  if oid in objects:row["revisions"][label]["captured_source"]=objects[oid]
 row["N_equals_N2"]=row["revisions"]["N"]["git_blob"]==row["revisions"]["N2"]["git_blob"]
 row["N_equals_R1"]=row["revisions"]["N"]["git_blob"]==row["revisions"]["R1"]["git_blob"]
 rows.append(row)
diff=git(["diff","--full-index",REV["N"],REV["R1"],"--",*paths])
with (D/"N-to-R1-selected-protocol.patch").open("xb") as f:f.write(diff)
summary={"schema":"trnm-N-N2-R1-selected-protocol-source-comparison-v1","revisions":REV,"no_lazy_fetch":True,"no_source_ref_mutation":True,"files":rows,"patch":{"bytes":len(diff),"sha256":hashlib.sha256(diff).hexdigest()}}
with (D/"summary.json").open("xb") as f:f.write((json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps(summary,sort_keys=True))
