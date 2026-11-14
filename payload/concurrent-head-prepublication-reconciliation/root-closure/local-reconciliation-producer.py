import datetime,hashlib,json,os,pathlib,subprocess
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
WT=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
EV=ROOT/"remote-head-drift-local-reconciliation-v1";EV.mkdir(mode=0o700,exist_ok=False)
env=dict(os.environ);env.update({"PATH":"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","PYTHONDONTWRITEBYTECODE":"1"})
steps=[]
def run(label,*args):
    q=subprocess.run(["git","--no-replace-objects",*args],cwd=WT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    row={"label":label,"argv":["git","--no-replace-objects",*args],"exit":q.returncode}
    for channel in ("stdout","stderr"):
        raw=getattr(q,channel);p=EV/(label+"."+channel);p.write_bytes(raw);row[channel]={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    steps.append(row);return q
head=run("source-head-before","rev-parse","HEAD")
status=run("source-status-before","status","--porcelain","--untracked-files=all","--ignore-submodules=none")
assert head.returncode==0 and head.stdout.decode().strip()=="2a62061177852dc3ebd200fa8d7c66c661a119a1" and status.returncode==0 and status.stdout==b""
new="5a4b7fe8de1adce803184f262fd9f704ead1930c"
q=run("local-new-commit-type","cat-file","-t",new)
extra={}
if q.returncode==0:
    assert q.stdout.strip()==b"commit"
    size=run("local-new-commit-size","cat-file","-s",new)
    assert size.returncode==0 and int(size.stdout)<=1048576
    raw=run("local-new-commit","cat-file","commit",new)
    assert raw.returncode==0
    extra["local_commit_raw"]=raw.stdout.decode("utf-8")
    for label,a,b in (("c0-to-new","dc42ce4df5cff79cc61c5addbaf01074b56b06ca",new),("new-to-m6",new,"2a62061177852dc3ebd200fa8d7c66c661a119a1"),("m6-to-new","2a62061177852dc3ebd200fa8d7c66c661a119a1",new)):
        extra[label]=run(label,"merge-base","--is-ancestor",a,b).returncode
f=ROOT/"remote-readonly-refresh-0170-v1/branches.json";b=f.read_bytes();assert hashlib.sha256(b).hexdigest()=="e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734"
data=json.loads(b);matches=[]
wanted={"fix/chain-hepta-closure-candidate-20261109-481716",new,"dc42ce4df5cff79cc61c5addbaf01074b56b06ca"}
def walk(x,path):
    if isinstance(x,dict):
        scalars={k:v for k,v in x.items() if v is None or isinstance(v,(str,int,float,bool))}
        for k,v in x.items():
            if k in wanted or isinstance(v,str) and v in wanted:matches.append({"path":path+[k],"value":v if isinstance(v,(str,int,float,bool)) else None,"parent_scalars":scalars})
            if isinstance(v,(dict,list)):walk(v,path+[k])
    elif isinstance(x,list):
        if any(isinstance(v,str) and v in wanted for v in x):matches.append({"path":path,"list_scalar_values":[v for v in x if isinstance(v,(str,int,float,bool))]})
        for i,v in enumerate(x):
            if isinstance(v,(dict,list)):walk(v,path+[i])
walk(data,[])
posthead=run("source-head-after","rev-parse","HEAD");poststatus=run("source-status-after","status","--porcelain","--untracked-files=all","--ignore-submodules=none")
assert posthead.returncode==0 and posthead.stdout==head.stdout and poststatus.returncode==0 and poststatus.stdout==status.stdout
out={"schema":"trnm-remote-head-drift-local-readonly-observation-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"new_api_head":new,"local_new_object_present":q.returncode==0,"local_object":extra,"frozen_inventory_matches":matches,"source_unchanged":True,"network_or_fetch_or_source_mutation":False,"steps":steps}
raw=(json.dumps(out,indent=2)+"\n").encode();(EV/"summary.json").write_bytes(raw)
print(json.dumps({"path":str(EV/"summary.json"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"observation":{k:v for k,v in out.items() if k!="steps"}}),flush=True)
