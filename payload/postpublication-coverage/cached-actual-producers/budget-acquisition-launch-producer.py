import ast,hashlib,json,os,sys
from pathlib import Path
out=Path("/private/tmp/chain-prci-R1-budget-three-artifact-acquisition-preparation-20261114-v1")
out.mkdir(mode=0o700,exist_ok=False)
p=out/"acquire_three_budget_artifacts_v1.py";raw=sys.argv[1].encode()
compile(raw,str(p),"exec",dont_inherit=True,optimize=0);ast.parse(raw)
with p.open("xb")as f:f.write(raw)
if p.read_bytes()!=raw:raise ValueError("READBACK")
print(json.dumps({"producer":{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"mode":"authorized_single_acquisition","max_GETs":6,"no_retry":True}),flush=True)
env=os.environ.copy();env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["PYTHONDONTWRITEBYTECODE"]="1";env["PYTHONOPTIMIZE"]="0"
os.execve(sys.executable,[sys.executable,"-B",str(p)],env)
