import collections,datetime,hashlib,json,os,pathlib,subprocess,sys
assert not sys.flags.optimize
B=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root");W=B/"source";E=B/"P1-index-flag-diagnostic-v1";E.mkdir(mode=0o700)
(E/"producer.py").write_text(sys.argv[1]);env=dict(os.environ,GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1")
steps=[]
def run(label,args,allowed=(0,)):
 r=subprocess.run(["git","-C",str(W),*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 for suffix,raw in (("stdout",r.stdout),("stderr",r.stderr)):(E/(label+"."+suffix)).write_bytes(raw)
 steps.append({"label":label,"args":args,"exit":r.returncode,"stdout_bytes":len(r.stdout),"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest()});assert r.returncode in allowed
 return r.stdout
head=run("head",["rev-parse","HEAD"]).decode().strip();tree=run("tree",["rev-parse","HEAD^{tree}"]).decode().strip();status=run("status",["status","--porcelain=v1","--untracked-files=all"])
assert head=="6a8cd55573065ceb50cdb65a7834615f79b521ae" and tree=="cbd6b4552c87af27c72c0189806baeb33ecb8bf5" and not status
raw=run("ls-files-v",["ls-files","-v","-z"]);parts=raw.split(b"\0");assert parts[-1]==b""
rows=[{"flag":x[:1].decode(),"path":x[2:].decode()} for x in parts[:-1]];assert all(len(x)>2 and x[1:2]==b" " for x in parts[:-1])
flags=[x for x in rows if x["flag"]!="H"]
settings={}
for key in ("core.ignorestat","core.fsmonitor","core.untrackedcache","core.preloadindex","core.sparsecheckout"):
 settings[key]=run("config-"+key,["config","--show-origin","--get-all",key],(0,1)).decode()
index_path=pathlib.Path(run("index-path",["rev-parse","--git-path","index"]).decode().strip());index_path=index_path if index_path.is_absolute() else W/index_path;index=index_path.read_bytes()
s={"schema":"trnm-P1-index-flag-diagnostic-v1","head":head,"tree":tree,"status_clean":True,"entry_count":len(rows),"flag_counts":dict(collections.Counter(x["flag"] for x in rows)),"non_H":flags,"settings":settings,"index_path":str(index_path),"index_bytes":len(index),"index_sha256":hashlib.sha256(index).hexdigest(),"steps":steps,"source_or_index_mutation":False,"time":datetime.datetime.now(datetime.timezone.utc).isoformat()}
(E/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n");print(json.dumps(s),flush=True)
