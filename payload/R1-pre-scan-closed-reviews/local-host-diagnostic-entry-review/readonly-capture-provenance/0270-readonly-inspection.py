import ast, hashlib, json, os, pathlib, stat, subprocess
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1")
E.mkdir(exist_ok=False)
(E/"source-capture-v1").mkdir()
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
H="2a86462a1ab20c68151719ba4635e3c294391e64"
T="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
commands=[]
def g(label,args):
 a=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never",*args]
 c=subprocess.run(a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 for s,b in [("stdout",c.stdout),("stderr",c.stderr)]:
  (E/(label+"."+s)).write_bytes(b)
 commands.append({"label":label,"argv":a,"exit":c.returncode,"stdout_bytes":len(c.stdout),"stdout_sha256":hashlib.sha256(c.stdout).hexdigest(),"stderr_bytes":len(c.stderr),"stderr_sha256":hashlib.sha256(c.stderr).hexdigest()})
 if c.returncode:raise RuntimeError(label)
 return c.stdout
commit=g("commit",["cat-file","commit",H])
if commit.splitlines()[0]!=("tree "+T).encode():raise ValueError("FIXED_TREE")
paths=["scripts/ci/public_host_ci_observation.py","trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs"]
files=[]
for path in paths:
 raw=g("source-"+path.replace("/","--"),["cat-file","blob",H+":"+path])
 oid=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
 dest=E/"source-capture-v1"/(path.replace("/","--")+".raw")
 dest.write_bytes(raw)
 files.append({"path":path,"source_head":H,"git_oid":oid,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"capture":str(dest)})
native=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1/protocol-source-comparison-v1/scripts--ci--run_from_zero_native.py.2aba481576bc5a09a2d546e467e1b19d6e9de7bd.raw")
raw=native.read_bytes()
assert len(raw)==115087 and hashlib.sha256(raw).hexdigest()=="3f497112a01f71f7259a1e12fff48f2a38499e396dae591692d623813bd6b5b0"
parsed=ast.parse(raw)
defs=[{"name":n.name,"start":n.lineno,"end":n.end_lineno} for n in parsed.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
(E/"native-definition-index.json").write_text(json.dumps(defs,indent=2)+"\n")
selected=[]
for i,s in enumerate(raw.decode().splitlines(),1):
 if any(k in s for k in ("GITHUB_ACTIONS","def main","def source_identity","TESTS =","WINDOW","ATTACK","--out","CARGO","CONFIRMATION","def native_build","def run_test","def run_child","def validate_confirmation","def confirmation")):
  selected.append({"line":i,"text":s})
(E/"native-selected-lines.json").write_text(json.dumps(selected,indent=2)+"\n")
listing=g("source-paths",["ls-tree","-r","--name-only",H,".github/workflows","config/systemd","trillionnium/crates/trnm-pon-node/src/ingress/public_v3"])
(E/"source-index.json").write_text(json.dumps({"head":H,"tree":T,"files":files,"commands":commands},indent=2)+"\n")
print(json.dumps({"evidence_dir":str(E),"native_definitions":defs,"native_selected_lines":selected,"source_paths":listing.decode().splitlines(),"files":files},sort_keys=True))
