import hashlib,json,os,pathlib,stat,subprocess,sys
B=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root");W=B/"source";E=B/"P1-sparse-checkout-precorrection-v1";E.mkdir(mode=0o700);(E/"producer.py").write_text(sys.argv[1]);env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
paths=["evidence/pon-joint-resource-contract-20261109/archives/original-campaign-42553751914.zip","evidence/pq-authority-preflight-20261108-9d315/hosted-ci-native-triage-01/native-campaign-artifact-13610289272/original-artifact-13610289272.zip"]
def git(*args):return subprocess.check_output(["git","-C",str(W),*args],env=env,timeout=60)
assert git("rev-parse","HEAD").decode().strip()=="6a8cd55573065ceb50cdb65a7834615f79b521ae"
raw=git("ls-tree","-l","HEAD","--",*paths);(E/"two-tree-entries.stdout").write_bytes(raw)
rows=[]
for line in raw.decode().splitlines():
 meta,path=line.split("\t",1);mode,kind,oid,size=meta.split();assert path in paths and kind=="blob" and mode=="100644";f=W/path
 if f.exists():
  st=f.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1;h=hashlib.sha1(b"blob "+size.encode()+b"\0",usedforsecurity=False);n=0
  with f.open("rb") as stream:
   while chunk:=stream.read(1048576):h.update(chunk);n+=len(chunk)
  assert n==int(size) and h.hexdigest()==oid;physical={"exists":True,"bytes":n,"blob_verified":True}
 else:physical={"exists":False}
 rows.append({"path":path,"blob":oid,"bytes":int(size),"physical":physical})
assert len(rows)==2
cfg=git("rev-parse","--git-path","config.worktree").decode().strip();pat=git("rev-parse","--git-path","info/sparse-checkout").decode().strip();stored=[]
for label,path in (("config.worktree",cfg),("sparse-checkout",pat)):
 f=pathlib.Path(path);f=f if f.is_absolute() else W/f
 b=f.read_bytes();assert len(b)<65536;(E/(label+".original")).write_bytes(b);stored.append({"label":label,"path":str(f),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
s={"schema":"trnm-P1-sparse-precorrection-v1","paths":rows,"settings_saved":stored,"disk_free_bytes":__import__("shutil").disk_usage(B).free,"source_or_git_mutation":False};(E/"summary.json").write_text(json.dumps(s,indent=2)+"\n");print(json.dumps(s),flush=True)
