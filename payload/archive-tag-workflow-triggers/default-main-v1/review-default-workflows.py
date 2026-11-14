import os,sys,stat,hashlib,json,subprocess,datetime,time
from pathlib import Path
import yaml
SRC=Path("/private/tmp/chain-consolidation-20261114-mainline")
OUT=Path("/private/tmp/chain-R1-archive-tag-workflow-trigger-review-20261114-v1/default-main-v1")
B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
R1="2a86462a1ab20c68151719ba4635e3c294391e64"
def need(ok,m):
    if not ok: raise ValueError(m)
def sha(b): return hashlib.sha256(b).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
os.umask(0o077); OUT.mkdir()
env=os.environ.copy(); env.update({"GIT_OPTIONAL_LOCKS":"0","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_TERMINAL_PROMPT":"0","GIT_ALLOW_PROTOCOL":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONOPTIMIZE":"0"})
def put(name,b):
    p=OUT/name; p.parent.mkdir(parents=True,exist_ok=True)
    need(p.parent.resolve(strict=True)==p.parent,"OUTPUT_PARENT")
    with p.open("xb") as f: f.write(b)
    need(p.read_bytes()==b,"READBACK")
    return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def jp(name,v): return put(name,(json.dumps(v,sort_keys=True,indent=2)+"\n").encode())
steps=[]
def git(label,args,data=None,cap=2*1024*1024):
    argv=["/usr/bin/git","--no-replace-objects","-c","protocol.allow=never","-C",str(SRC)]+args
    start=now();t=time.monotonic()
    try:r=subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd="/private/tmp",timeout=60)
    except subprocess.TimeoutExpired as e:r=subprocess.CompletedProcess(argv,124,e.stdout or b"",e.stderr or b"")
    need(len(r.stdout)<=cap and len(r.stderr)<=65536,"COMMAND_CAPTURE_BOUND")
    steps.append({"label":label,"argv":argv,"cwd":"/private/tmp","started_at":start,"finished_at":now(),"elapsed_seconds":time.monotonic()-t,"exit":r.returncode,"timeout_seconds":60,"stdout":put(label+".stdout",r.stdout),"stderr":put(label+".stderr",r.stderr)})
    need(r.returncode==0,"READ_ONLY_GIT_FAILED_"+label)
    return r.stdout
before=git("source-head-before",["rev-parse","HEAD","HEAD^{tree}"]).decode().splitlines()
trees=git("fixed-workflow-trees",["rev-parse",B+"^{commit}",B+":.github/workflows",R1+"^{commit}",R1+":.github/workflows"]).decode().splitlines()
need(len(trees)==4 and trees[0]==B and trees[2]==R1,"FIXED_IDENTITIES")
rows=[]
if trees[1]!=trees[3]:
    listing=git("B-workflow-list",["ls-tree","-r","-z",B,"--",".github/workflows"])
    for rec in listing.split(b"\0"):
        if not rec:continue
        left,path=rec.split(b"\t",1); mode,typ,oid=left.decode().split(); path=path.decode()
        need(mode=="100644" and typ=="blob" and path.startswith(".github/workflows/") and path.endswith((".yml",".yaml")),"WORKFLOW_MODE_PATH")
        rows.append({"path":path,"oid":oid,"mode":mode})
    need(0<len(rows)<=256,"WORKFLOW_COUNT")
    oids=list(dict.fromkeys(row["oid"] for row in rows))
    raw=git("B-workflow-blobs",["cat-file","--batch"],("\n".join(oids)+"\n").encode(),cap=4*1024*1024)
    cursor=0; contents={}
    for oid in oids:
        end=raw.index(b"\n",cursor);header=raw[cursor:end].decode().split();cursor=end+1
        need(len(header)==3 and header[0]==oid and header[1]=="blob","BATCH_HEADER")
        n=int(header[2]);need(0<=n<=128*1024,"BLOB_BOUND")
        b=raw[cursor:cursor+n];cursor+=n;need(raw[cursor:cursor+1]==b"\n","BATCH_NEWLINE");cursor+=1
        need(len(b)==n and hashlib.sha1(b"blob "+str(n).encode()+b"\0"+b).hexdigest()==oid,"CONTENT_ADDRESS")
        contents[oid]=b
    need(cursor==len(raw),"BATCH_TRAILER")
    for row in rows:
        b=contents[row["oid"]];row["source"]=put("sources/"+row["path"],b)
        y=yaml.load(b.decode(),Loader=yaml.BaseLoader);need(type(y) is dict and "on" in y,"WORKFLOW_ON")
        row["events"]=y["on"]
        row["lines"]=[{"line":i+1,"text":s} for i,s in enumerate(b.decode().splitlines()) if i<40 or any(x in s.lower() for x in ("workflow_run","release","deploy","promot","publish","tags:","tags-ignore","create:","environment:","workflow_call","ref_type","ref_name","refs/tags","event_name"))]
after=git("source-head-after",["rev-parse","HEAD","HEAD^{tree}"]).decode().splitlines()
need(before==after,"SOURCE_CHANGED")
summary={"schema":"trnm-default-main-workflow-trigger-review-v1","base":B,"candidate":R1,"base_workflow_tree":trees[1],"candidate_workflow_tree":trees[3],"trees_identical":trees[1]==trees[3],"source_before":before,"source_after":after,"source_unchanged":True,"workflow_count":len(rows),"workflows":rows,"steps":steps,"scope":"Immutable GitHub Actions declarations only; no claim about external webhooks or Apps.","no_network_tests_or_workflow_execution":True,"source_refs_stage_config_unmodified":True}
put("review-default-workflows.py",sys.argv[1].encode())
sp=jp("summary.json",summary)
print(json.dumps({"summary":sp,"trees_identical":summary["trees_identical"],"base_workflow_tree":trees[1],"candidate_workflow_tree":trees[3],"workflow_count":len(rows),"events":[{"path":x["path"],"oid":x["oid"],"events":x["events"],"sha256":x["source"]["sha256"]} for x in rows]},sort_keys=True))
