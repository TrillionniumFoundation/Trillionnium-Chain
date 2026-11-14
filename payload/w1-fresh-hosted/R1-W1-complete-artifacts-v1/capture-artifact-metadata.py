import concurrent.futures, datetime, hashlib, json, os, pathlib, subprocess, sys, time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1")
E.mkdir(mode=0o700)
SHA=lambda b:hashlib.sha256(b).hexdigest()
def write(p,b):
    with p.open("xb") as f:f.write(b)
def jb(x):return (json.dumps(x,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
write(E/"capture-artifact-metadata.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k not in ("GH_DEBUG","GIT_CURL_VERBOSE")}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_TRACE="0",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
jobs=[
{"kind":"head","job_id":132475259337,"id":14117751904,"name":"w1-fresh-service-head-2a86462a1ab20c68151719ba4635e3c294391e64-1","size":6479218,"sha256":"b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8"},
{"kind":"prospective-merge","job_id":132475258996,"id":14117403147,"name":"w1-fresh-service-prospective-merge-a7ee9542d10e15bba4256de9579a0196ba9ab9c9-1","size":6451341,"sha256":"2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a"}]
def fi(p):
    b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":SHA(b)}
def one(j):
    label="artifact-"+str(j["id"])+"-metadata"
    args=["/opt/homebrew/bin/gh","api","--hostname","github.com","--include","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10",f"repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/{j['id']}"]
    out=E/(label+".stdout");err=E/(label+".stderr")
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();code=None;exc=None
    with out.open("xb") as o,err.open("xb") as e:
        try:code=subprocess.run(args,cwd="/private/tmp",env=env,stdout=o,stderr=e,timeout=180,check=False).returncode
        except subprocess.TimeoutExpired:code=124;exc="timeout"
    step={"label":label,"argv":args,"cwd":"/private/tmp","started_at":start,"completed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"duration_seconds":time.monotonic()-t,"timeout_seconds":180,"exit_code":code,"error":exc,"stdout":fi(out),"stderr":fi(err)}
    write(E/(label+".step.json"),jb(step))
    r={"expected_from_original_log":j,"step":step,"valid":False}
    if code!=0:return r
    raw=out.read_bytes()
    if len(raw)>2*1024*1024:raise ValueError("metadata exceeds cap")
    split=raw.split(b"\r\n\r\n",1) if b"\r\n\r\n" in raw else raw.split(b"\n\n",1)
    if len(split)!=2:raise ValueError("metadata headers missing")
    headers,body=split
    if not headers.splitlines()[0].endswith(b"200 OK"):raise ValueError("metadata not HTTP 200")
    value=json.loads(body)
    wr=value.get("workflow_run",{})
    checks={
      "id":value.get("id")==j["id"],
      "name":value.get("name")==j["name"],
      "size":value.get("size_in_bytes")==j["size"],
      "digest":value.get("digest")=="sha256:"+j["sha256"],
      "not_expired":value.get("expired") is False,
      "workflow_run":wr.get("id")==43604217632,
      "head":wr.get("head_sha")=="2a86462a1ab20c68151719ba4635e3c294391e64",
    }
    r.update(actual=value,checks=checks,valid=all(checks.values()))
    return r
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(one,jobs))
summary={"schema":"trnm-r1-fresh-service-artifact-metadata-v1","read_only":True,"source":"original complete job logs cross-checked with live API metadata","run_id":43604217632,"run_attempt":1,"results":results,"all_valid":all(r["valid"] for r in results)}
write(E/"metadata-summary.json",jb(summary))
print(json.dumps({"all_valid":summary["all_valid"],"summary":fi(E/"metadata-summary.json"),"results":[{"id":r["expected_from_original_log"]["id"],"valid":r["valid"],"checks":r.get("checks"),"exit_code":r["step"]["exit_code"],"stdout":r["step"]["stdout"],"stderr":r["step"]["stderr"]} for r in results]},sort_keys=True))
