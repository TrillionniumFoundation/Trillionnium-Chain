import os,sys,stat,hashlib,json,subprocess,datetime,time
from pathlib import Path
SRC=Path("/private/tmp/chain-consolidation-20261114-mainline")
OUT=Path("/private/tmp/chain-R1-archive-tag-workflow-trigger-review-20261114-v1")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
TAG="archive/post-publication-diagnostics-20261114-2a86462a1ab2-v1"
def need(ok,m):
    if not ok:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
os.umask(0o077);OUT.mkdir()
env=os.environ.copy();env.update({"GIT_OPTIONAL_LOCKS":"0","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_TERMINAL_PROMPT":"0","GIT_ALLOW_PROTOCOL":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONOPTIMIZE":"0"})
def put(name,b):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    need(p.parent.resolve(strict=True)==p.parent,"OUTPUT_PARENT")
    with p.open("xb") as f:f.write(b)
    need(p.read_bytes()==b,"READBACK")
    return{"path":str(p),"bytes":len(b),"sha256":sha(b)}
def jp(name,v):return put(name,(json.dumps(v,indent=2,sort_keys=True)+"\n").encode())
steps=[]
def git(label,args,data=None,cap=2*1024*1024):
    argv=["/usr/bin/git","--no-replace-objects","-c","protocol.allow=never","-C",str(SRC)]+args
    start=now();t=time.monotonic()
    try:r=subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd="/private/tmp",timeout=60)
    except subprocess.TimeoutExpired as e:
        r=subprocess.CompletedProcess(argv,124,e.stdout or b"",e.stderr or b"")
    need(len(r.stdout)<=cap and len(r.stderr)<=65536,"COMMAND_CAPTURE_BOUND")
    rec={"label":label,"argv":argv,"cwd":"/private/tmp","started_at":start,"finished_at":now(),"elapsed_seconds":time.monotonic()-t,"exit":r.returncode,"timeout_seconds":60,"stdout":put(label+".stdout",r.stdout),"stderr":put(label+".stderr",r.stderr)}
    steps.append(rec);need(r.returncode==0,"READONLY_GIT_FAILED_"+label);return r.stdout
before=git("head-before",["rev-parse","HEAD","HEAD^{tree}"]).decode().splitlines()
fixed=git("fixed-source",["rev-parse",HEAD+"^{commit}",HEAD+"^{tree}"]).decode().splitlines()
need(fixed==[HEAD,TREE],"FIXED_R1")
listing=git("workflow-tree",["ls-tree","-r","-z",HEAD,"--",".github/workflows"])
rows=[]
for rec in listing.split(b"\0"):
    if not rec:continue
    left,p=rec.split(b"\t",1);mode,typ,oid=left.decode().split();path=p.decode()
    need(mode=="100644" and typ=="blob" and path.startswith(".github/workflows/"),"WORKFLOW_OBJECT_MODE")
    need(path.endswith((".yml",".yaml")),"UNEXPECTED_WORKFLOW_EXTENSION")
    rows.append({"path":path,"oid":oid,"mode":mode})
need(0<len(rows)<=256,"WORKFLOW_COUNT")
oids=list(dict.fromkeys(r["oid"] for r in rows))
raw=git("workflow-blobs",["cat-file","--batch"],("\n".join(oids)+"\n").encode(),cap=4*1024*1024)
cursor=0;contents={}
for oid in oids:
    end=raw.index(b"\n",cursor);header=raw[cursor:end].decode().split();cursor=end+1
    need(len(header)==3 and header[0]==oid and header[1]=="blob","BATCH_HEADER")
    n=int(header[2]);need(0<=n<=128*1024,"BLOB_BOUND")
    b=raw[cursor:cursor+n];cursor+=n;need(raw[cursor:cursor+1]==b"\n","BATCH_NEWLINE");cursor+=1
    need(hashlib.sha1(b"blob "+str(n).encode()+b"\0"+b).hexdigest()==oid,"CONTENT_ADDRESS")
    contents[oid]=b
need(cursor==len(raw),"BATCH_TRAILER")
for row in rows:row["source"]=put("sources/"+row["path"],contents[row["oid"]])
after=git("head-after",["rev-parse","HEAD","HEAD^{tree}"]).decode().splitlines()
need(before==after,"LIVE_HEAD_CHANGED")
index=jp("source-index.json",{"schema":"trnm-r1-archive-tag-workflow-source-index-v1","head":HEAD,"tree":TREE,"tag_candidate":TAG,"live_before":before,"live_after":after,"live_identity_unchanged":True,"read_only_git_environment":{"GIT_OPTIONAL_LOCKS":"0","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_ALLOW_PROTOCOL":""},"workflow_count":len(rows),"files":rows,"steps":steps,"no_workflow_tests_or_network_executed":True,"source_refs_stage_config_unmodified":True})
put("capture-workflow-blobs.py",sys.argv[1].encode())
excerpts=[]
for row in rows:
    lines=contents[row["oid"]].decode().splitlines()
    chosen=[{"line":i+1,"text":s} for i,s in enumerate(lines) if i<45 or any(x in s.lower() for x in ("workflow_run","release","deploy","promot","publish","tags:","tags-ignore","create:","environment:","permissions:","workflow_call","ref_type","ref_name","refs/tags","event_name","branches:","branches-ignore"))]
    excerpts.append({"path":row["path"],"oid":row["oid"],"source":row["source"],"excerpts":chosen})
ep=jp("trigger-and-action-excerpts.json",excerpts)
print(json.dumps({"index":index,"excerpts":ep,"workflow_count":len(rows),"source_before_after":before,"files":[{"path":r["path"],"bytes":r["source"]["bytes"],"oid":r["oid"]} for r in rows]},sort_keys=True))
