import pathlib,os,stat,sys,json,hashlib,datetime,subprocess,time
G=pathlib.Path("/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git")
O=pathlib.Path("/private/tmp/chain-prci-N2-w1-ci-review-20261114-v1");assert not O.exists();O.mkdir(mode=0o700)
REV={"N":"5a4b7fe8de1adce803184f262fd9f704ead1930c","N2":"096c6b5f9b952c49389fd975515744074ba61317","P2":"1e54c4ff66a92827c83bea8715f59f6b299e98cf"}
PATHS=[".github/workflows/pon-w1-work-security.yml","scripts/ci/test_w1_v2_controls_gate.py","scripts/ci/w1_v2_controls_gate.py"]
env=os.environ.copy()
for k in tuple(env):
 if k.startswith("GIT_TRACE")or k=="GIT_CURL_VERBOSE":del env[k]
env.update(GIT_OPTIONAL_LOCKS="0",GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1")
for k in("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_NAMESPACE","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"):assert k not in env
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def save(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return{"path":str(p),"bytes":len(b),"sha256":sha(b)}
steps=[]
def git(label,args,cap=2*1024*1024):
 argv=["/usr/bin/git","--no-replace-objects","--git-dir="+str(G)]+args
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();r=subprocess.run(argv,cwd="/private/tmp",env=env,capture_output=True,timeout=60)
 assert len(r.stdout)<=cap and len(r.stderr)<=65536
 out=save(O/"raw"/(label+".stdout"),r.stdout);err=save(O/"raw"/(label+".stderr"),r.stderr)
 steps.append({"label":label,"argv":argv,"started_at":start,"elapsed_seconds":round(time.monotonic()-t,6),"exit":r.returncode,"stdout":out,"stderr":err})
 assert r.returncode==0,(label,r.returncode,r.stderr.decode(errors="replace"))
 return r.stdout
save(O/"extract-producer.py",sys.argv[1].encode())
commits={};rows=[]
for name,commit in REV.items():
 raw=git(name+"-commit",["cat-file","commit",commit],131072)
 assert hashlib.sha1(b"commit "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==commit
 header,message=raw.split(b"\n\n",1);pairs=[line.decode().split(" ",1)for line in header.splitlines()if line.startswith((b"tree ",b"parent "))]
 commits[name]={"commit":commit,"tree":[v for k,v in pairs if k=="tree"][0],"parents":[v for k,v in pairs if k=="parent"],"message":message.decode()}
 listing=git(name+"-tree",["ls-tree",commit,"--"]+PATHS).decode()
 entries={}
 for line in listing.splitlines():
  mode,kind,oid_and_path=line.split(" ",2);oid,path=oid_and_path.split("\t",1)
  assert kind=="blob" and mode in("100644","100755") and path not in entries;entries[path]=(mode,oid)
 assert set(entries)==set(PATHS)
 for i,path in enumerate(PATHS):
  mode,oid=entries[path];raw=git(name+"-source-"+str(i),["cat-file","blob",oid])
  assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid
  p=save(O/"sources"/name/(path.replace("/","--")+".source"),raw)
  rows.append({"revision":name,"commit":commit,"tree":commits[name]["tree"],"repository_path":path,"mode":mode,"git_blob":oid,**p})
assert commits["N2"]["parents"]==[REV["N"]] and commits["N2"]["tree"]=="aab22f6d1bdff4aa55a79a1e9136f14490c6b057"
assert commits["P2"]["tree"]=="2c0716f9165f7cbc31ce8eae17f17bf2643d30cb"
diffs=[]
for a,b in[("N","N2"),("N","P2"),("P2","N2")]:
 raw=git(a+"-to-"+b+"-diff",["--no-pager","diff","--no-ext-diff","--no-textconv","--full-index",REV[a],REV[b],"--"]+PATHS)
 diffs.append({"from":a,"to":b,**save(O/(a+"-to-"+b+".patch"),raw)})
index={"schema":"trnm-N-N2-P2-three-W1-CI-sources-v1","created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"git_dir":str(G),"commits":commits,"repository_paths":PATHS,"files":rows,"diffs":diffs,"git_commands_readonly":True,"git_network_or_lazy_fetch":False,"tests_or_source_or_stage_actions":False}
ip=save(O/"source-index.json",js(index));sp=save(O/"steps.json",js(steps))
print(json.dumps({"index":ip,"steps":sp,"commits":commits,"files":rows,"diffs":diffs}),flush=True)
