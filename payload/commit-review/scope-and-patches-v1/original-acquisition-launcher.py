import os,sys,hashlib,stat,json
from pathlib import Path
p=Path("/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1-producer.py")
data=sys.argv[1].encode();assert sys.flags.optimize==0
compile(data,str(p),"exec",optimize=0)
with p.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and p.read_bytes()==data
print(json.dumps({"producer":{"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},"scope":"exactly two authorized GETs, overall300s, no retries"}),flush=True)
env=os.environ.copy();env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["PYTHONDONTWRITEBYTECODE"]="1";env["PYTHONOPTIMIZE"]="0"
os.execve(sys.executable,[sys.executable,"-B",str(p)],env)
