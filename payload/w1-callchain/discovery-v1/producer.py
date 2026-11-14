import os,sys,json,subprocess,hashlib,datetime
from pathlib import Path
assert sys.flags.optimize==0
D=Path("/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1/discovery-v1");D.mkdir(parents=True,exist_ok=False)
G="/usr/bin/git";DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="5df7ae6f482157c5f7fdcbcd52222117a965053f"
env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0")
def put(n,b):
 p=D/n
 with p.open("xb")as f:f.write(b)
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
put("producer.py",sys.argv[1].encode())
cmds=[
 ("entrypoints",[G,"--git-dir="+DB,"grep","-n","-E","struct WorkCheckedPacket|impl WorkCheckedPacket|fn verify_with_progress|struct ThreadCpuStamp|impl ThreadCpuStamp",H,"--","trillionnium/crates/trnm-pon-node/src","trillionnium/crates/trnm-protocol/src"]),
 ("work-paths",[G,"--git-dir="+DB,"ls-tree","-r","--name-only",H,"--","trillionnium/crates/trnm-protocol/src/pon_work","trillionnium/crates/trnm-protocol/src/pon_work.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/history_import.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"])]
rows=[]
for label,argv in cmds:
 s=datetime.datetime.now(datetime.timezone.utc).isoformat();r=subprocess.run(argv,capture_output=True,timeout=40,env=env)
 rows.append({"label":label,"argv":argv,"exit":r.returncode,"started_at":s,"stdout":put(label+".stdout",r.stdout),"stderr":put(label+".stderr",r.stderr)})
 assert r.returncode==0
put("summary.json",(json.dumps({"read_only":True,"head":H,"rows":rows},sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"directory":str(D),"commands":rows,"entrypoints":(D/"entrypoints.stdout").read_text(),"paths":(D/"work-paths.stdout").read_text()},sort_keys=True))
