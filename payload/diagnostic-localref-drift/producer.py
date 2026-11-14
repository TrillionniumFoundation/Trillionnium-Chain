import datetime,hashlib,json,os,pathlib,re,stat,sys
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
OUT=ROOT/"R1-diagnostic-resume-local-ref-drift-review-v1"
OLD={"path":str(ROOT/"r1-diagnostic-stage1-publish-v1-r1-001/summary.json"),"bytes":342603,"sha256":"cabdb51529518374495ffefd5da7d776b65e5836c28c390b03a2837d9a82256b"}
NEW={"path":str(ROOT/"r1-diagnostic-stage1-publish-v1-r1-after-5df-resume-001/summary.json"),"bytes":24978,"sha256":"7a6818cb96b460ac56cf317ef1220a8b101f63281dc662c1a0554a8f6632806e"}
DRIVER={"path":str(ROOT/"R1-diagnostic-tag-resume-preparation-v2/resume_diagnostic_stage1_v2.py"),"bytes":43785,"sha256":"e82bdcc48728032ef3a5f8c34740614559e0082d86066f327dba0bb13c1d429e"}
def need(v,m):
    if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(x):return (json.dumps(x,indent=2,sort_keys=True)+"\n").encode()
def fp(s):return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns
seen={}
def read(pin):
    p=pathlib.Path(pin["path"]);need(p.is_relative_to(ROOT) and p.resolve(strict=True)==p,"canonical fixed input")
    s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==pin["bytes"]<=1024*1024,"regular bounded input")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(fp(os.fstat(fd))==fp(s),"open identity")
        with os.fdopen(fd,"rb",closefd=False) as f:b=f.read(pin["bytes"]+1)
        need(fp(os.fstat(fd))==fp(s),"stable FD")
    finally:os.close(fd)
    need(fp(p.lstat())==fp(s) and len(b)==pin["bytes"] and sha(b)==pin["sha256"],"exact bytes")
    seen[str(p)]=(pin,fp(s));return b
o=json.loads(read(OLD));n=json.loads(read(NEW));driver=read(DRIVER).decode()
need(o["status"]=="UNKNOWN" and o["push_exit"]==128 and n["status"]=="HOLD"
     and n["push_started"] is False and n["dispatch_started"] is False,"actual unchanged terminal boundaries")
def stream(summary,label):
    rows=[x for x in summary["steps"] if x["label"]==label];need(len(rows)==1,"one step")
    row=rows[0]
    need(row["argv"]==["git","--no-replace-objects","for-each-ref","--format=%(refname) %(objectname)"]
         and row["cwd"]=="/private/tmp/chain-consolidation-20261114-mainline"
         and type(row["exit"]) is int and row["exit"]==0,"same exact successful local refs command")
    pin={k:row["stdout_"+k] for k in ("path","bytes","sha256")}
    err={k:row["stderr_"+k] for k in ("path","bytes","sha256")}
    raw=read(pin);need(read(err)==b"","empty original stderr")
    refs={}
    for line in raw.decode("ascii").splitlines():
        parts=line.split()
        need(len(parts)==2 and parts[0].startswith("refs/") and parts[0] not in refs
             and re.fullmatch(r"[0-9a-f]{40}",parts[1]),"unique ref record")
        refs[parts[0]]=parts[1]
    return refs,pin,raw,row
before,bp,br,brow=stream(o,"local-refs-before")
old,op,orr,orow=stream(o,"local-refs-after-publication")
cur,np,nrr,nrow=stream(n,"local-refs-before")
tag="refs/tags/diagnostic/r1-native-stage1-20261114-r1-v3"
need(tag not in before and old==dict(before,**{tag:"bec22f093723cae0bb4625bd1fcbe9858d61f68b"}),"original sole local creation")
added={k:cur[k] for k in sorted(cur.keys()-old.keys())}
removed={k:old[k] for k in sorted(old.keys()-cur.keys())}
changed={k:{"old":old[k],"new":cur[k]} for k in sorted(old.keys()&cur.keys()) if old[k]!=cur[k]}
delta={"original_count":len(old),"current_count":len(cur),"added":added,"removed":removed,"changed":changed,
       "unchanged_count":sum(old[k]==cur[k] for k in old.keys()&cur.keys()),"inputs":{"original":op,"current":np}}
labels=[x["label"] for x in n["steps"]]
need(not any(x.startswith(("hook-initial","hook-after-publication","remote-","actor-","atomic-","dispatch-")) for x in labels),
     "no live hook/remote/push/dispatch step was reached")
guard_init=driver.index("    guard=None\n")
first_refs=driver.index('need(refs("local-refs-before")==before_refs')
guard_assign=driver.index('guard=hook_guard("hook-initial")')
finally_guard=driver.index('need(guard is not None and hook_guard("hook-after-publication")==guard')
need(guard_init<first_refs<guard_assign<finally_guard,"guard execution order")
sources={}
for field in ("head","tree","status","symbolic"):
    aa=[x for x in n["steps"] if x["label"]=="source-initial-"+field]
    bb=[x for x in n["steps"] if x["label"]=="source-after-publication-"+field]
    need(len(aa)==len(bb)==1 and aa[0]["exit"]==bb[0]["exit"]==0,"actual before/after source identity steps")
    ap={k:aa[0]["stdout_"+k] for k in ("path","bytes","sha256")}
    bpp={k:bb[0]["stdout_"+k] for k in ("path","bytes","sha256")}
    a=read(ap);b=read(bpp);need(a==b,"unchanged actual source identity")
    sources[field]={"value":a.decode("utf8"),"before":ap,"after":bpp}
need(sources["head"]["value"]=="2a86462a1ab20c68151719ba4635e3c294391e64\n"
     and sources["tree"]["value"]=="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4\n"
     and sources["status"]["value"]=="","R1 source remains clean")
summary={"schema":"trnm-diagnostic-resume-local-ref-drift-review-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "read_only":True,"new_Git_API_commands":0,"source_or_refs_changed_by_review":False,
 "original_attempt":OLD,"new_attempt":NEW,"reviewed_driver":DRIVER,"delta":delta,
 "observations":{"original_local_after_time":orow["finished_at"],"new_local_before_time":nrow["finished_at"]},
 "source_identity_before_after":sources,"new_attempt_status":"HOLD","push_started":False,"dispatch_started":False,
 "secondary_error":{"message":"original hook/URL after publication",
 "reason":"guard remained None because the first local-ref equality check raised before hook_guard was invoked; Python and short-circuits.",
 "hook_before_or_after_read_performed":False,"configuration_drift_proven":False,
 "finally_following_ref_and_index_fences_reached":False},
 "source_after_valid_is_actual":n["source_after_valid"],
 "new_attempt_errors_preserved":n["errors"],"possible_writer_provenance":"Not inferred from ref spelling or identity; requires retained writer/ref-change evidence."}
for path,(pin,identity) in list(seen.items()):
    need(fp(pathlib.Path(path).lstat())==identity,"original metadata unchanged")
    read(pin)
need(not OUT.exists() and not OUT.is_symlink(),"create-only review")
OUT.mkdir(mode=0o700,exist_ok=False);os.umask(0o077)
files={"producer.py":sys.argv[1].encode(),"all-ref-delta.json":enc(delta),"summary.json":enc(summary)}
index=[]
for name,b in files.items():
    with (OUT/name).open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
    index.append({"path":str(OUT/name),"bytes":len(b),"sha256":sha(b)})
ib=enc({"files":index,"self_excluded":True,"source_inputs":[pin for pin,_ in seen.values()]})
with (OUT/"EVIDENCE_INDEX.json").open("xb") as f:f.write(ib);f.flush();os.fsync(f.fileno())
print(json.dumps({"delta":delta,"summary":index[-1],"index":{"path":str(OUT/"EVIDENCE_INDEX.json"),"bytes":len(ib),"sha256":sha(ib)},
 "secondary_error_is_uninitialized_baseline":True,"no_Git_API_or_source_ref_write":True}),flush=True)
