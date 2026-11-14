import os,sys,hashlib,difflib,ast
from pathlib import Path
D=Path("/private/tmp/chain-prci-H5DF-required-head-protocol-original-log-20261114-v1")
old,new=sys.argv[1:3]
assert hashlib.sha256(old.encode()).hexdigest()=="1f1b31e74c0a63892fb0f7d325b830b0f64e40a379cdaf30b965599fbe9c2604"
compile(new,"producer.py","exec",optimize=0);ast.parse(new)
D.mkdir(mode=0o700)
for name,raw in [("approved-capture-source.py",old),("producer.py",new),("service-to-required-protocol.patch","".join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile="approved-capture-source.py",tofile="producer.py")))]:
 with(D/name).open("x")as f:f.write(raw)
with(D/"launcher.py").open("x")as f:f.write(sys.argv[3])
env=dict(os.environ);env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["PYTHONOPTIMIZE"]="0";env["PYTHONDONTWRITEBYTECODE"]="1"
os.execve("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(D/"producer.py")],env)
