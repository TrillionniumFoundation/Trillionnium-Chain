import concurrent.futures,datetime,hashlib,json,os,pathlib,signal,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1")
SHA=lambda b:hashlib.sha256(b).hexdigest()
def write(p,b):
    with p.open("xb") as f:f.write(b)
def jb(x):return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
meta_raw=(E/"metadata-summary.json").read_bytes()
if len(meta_raw)!=6117 or SHA(meta_raw)!="2a538933fc2ffda93843423b2b3a75208343187596b2578fdd532b07b3324238":raise ValueError("metadata pin mismatch")
meta=json.loads(meta_raw)
if meta["all_valid"] is not True:raise ValueError("metadata not fully bound")
write(E/"download-complete-artifacts.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k not in ("GH_DEBUG","GIT_CURL_VERBOSE")}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_TRACE="0",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
def fi(p):
    b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":SHA(b)}
def one(r):
    j=r["actual"];i=j["id"];expected=r["expected_from_original_log"]
    if r["valid"] is not True or j["id"]!=expected["id"]:raise ValueError("unvalidated artifact")
    args=["/opt/homebrew/bin/gh","api","--hostname","github.com","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10",f"repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/{i}/zip"]
    out=E/(str(i)+".zip");err=E/(str(i)+".zip.stderr")
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();reason=None
    with out.open("xb") as o,err.open("xb") as e:
        proc=subprocess.Popen(args,cwd="/private/tmp",env=env,stdout=o,stderr=e,stdin=subprocess.DEVNULL,start_new_session=True)
        while proc.poll() is None:
            if out.stat().st_size>16*1024*1024 or err.stat().st_size>1024*1024:reason="output-cap"
            elif time.monotonic()-t>600:reason="timeout"
            if reason:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);proc.wait()
                break
            time.sleep(.25)
        actual_returncode=proc.wait()
    code=124 if reason=="timeout" else actual_returncode
    step={"label":"artifact-"+str(i)+"-complete-zip","artifact_id":i,"job_id":expected["job_id"],"source_kind":expected["kind"],"argv":args,"cwd":"/private/tmp","started_at":start,"completed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"duration_seconds":time.monotonic()-t,"timeout_seconds":600,"stdout_cap_bytes":16*1024*1024,"stderr_cap_bytes":1024*1024,"pid":proc.pid,"exit_code":code,"actual_returncode":actual_returncode,"stop_reason":reason,"stdout":fi(out),"stderr":fi(err)}
    step["size_matches_api"]=step["stdout"]["bytes"]==j["size_in_bytes"]
    step["digest_matches_api"]=j["digest"]=="sha256:"+step["stdout"]["sha256"]
    step["digest_matches_original_log"]=step["stdout"]["sha256"]==expected["sha256"]
    step["complete"]=code==0 and reason is None and all(step[k] for k in ["size_matches_api","digest_matches_api","digest_matches_original_log"])
    write(E/(str(i)+".zip.step.json"),jb(step));return step
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:steps=list(pool.map(one,meta["results"]))
result={"schema":"trnm-r1-fresh-service-complete-artifact-download-v1","read_only":True,"metadata":fi(E/"metadata-summary.json"),"steps":steps,"all_complete":all(s["complete"] for s in steps)}
write(E/"download-summary.json",jb(result))
print(json.dumps({"summary":fi(E/"download-summary.json"),"all_complete":result["all_complete"],"downloads":[{k:s[k] for k in ["artifact_id","exit_code","stop_reason","duration_seconds","stdout","stderr","complete"]} for s in steps]},sort_keys=True))
