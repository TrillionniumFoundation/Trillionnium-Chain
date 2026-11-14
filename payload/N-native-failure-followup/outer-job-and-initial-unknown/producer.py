import pathlib,os,stat,sys,json,hashlib,datetime,time,subprocess,selectors,signal,re
O=pathlib.Path("/private/tmp/chain-prci-N-cross-cost-job-log-review-20261114-v1")
SRC=pathlib.Path("/private/tmp/chain-prci-remote-5a4b-required-jobs-observation-20261114-v2")
EXPECTED_SUMMARY="511582eb74e1a0c01cdcf6e1f04a0e600169b34de314ff0e0fdde920badc61b3"
RUN=43582713392;X64=132415017426;ARM=132415017455;N="5a4b7fe8de1adce803184f262fd9f704ead1930c"
GH="/opt/homebrew/bin/gh";CAP=20*1024*1024;ERRCAP=1024*1024;BUDGET=120
assert not O.exists();O.mkdir(mode=0o700);os.umask(0o077)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def sg(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def rd(p):
 assert p.resolve(strict=True)==p
 f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(f);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
  with os.fdopen(f,"rb",closefd=False)as st:b=st.read(s.st_size+1)
  assert len(b)==s.st_size and sg(os.fstat(f))==sg(s)==sg(p.lstat());return b
 finally:os.close(f)
def save(name,b):
 p=O/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert rd(p)==b
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def fi(p):
 b=rd(p);return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
save("producer.py",sys.argv[1].encode())
sr=rd(SRC/"summary.json");assert sha(sr)==EXPECTED_SUMMARY;s=json.loads(sr)
assert s["fixed_required_run"]["id"]==RUN and s["fixed_required_run"]["head_sha"]==N
pins={t["label"]:t["stdout"]for t in s["steps"]}
rawjobs=rd(pathlib.Path(pins["N-required-jobs-page-001"]["path"]));assert len(rawjobs)==pins["N-required-jobs-page-001"]["bytes"]and sha(rawjobs)==pins["N-required-jobs-page-001"]["sha256"]
rawrun=rd(pathlib.Path(pins["N-required-run43582713392"]["path"]));assert len(rawrun)==pins["N-required-run43582713392"]["bytes"]and sha(rawrun)==pins["N-required-run43582713392"]["sha256"]
jobs=json.loads(rawjobs);run=json.loads(rawrun)
selected=[j for j in jobs["jobs"]if j["id"]in(X64,ARM)];assert len(selected)==2
for j in selected:assert j["run_id"]==RUN and j["head_sha"]==N and j["status"]=="completed" and j["conclusion"]=="failure"
identity={"schema":"trnm-N-cost-existing-job-metadata-v1","observation_started_at":s["started_at"],"observation_finished_at":s["finished_at"],"source_observation_summary":{"path":str(SRC/"summary.json"),"bytes":len(sr),"sha256":EXPECTED_SUMMARY},"run":{"id":RUN,"head_sha":N,"head_tree_from_run_metadata":run["head_commit"]["tree_id"],"run_attempt":run["run_attempt"],"event":run["event"]},"jobs":[{**{k:j.get(k)for k in("id","name","status","conclusion","started_at","completed_at","head_sha","run_id","run_attempt","html_url")},"failed_steps":[x for x in j["steps"]if x.get("conclusion")=="failure"],"all_steps":j["steps"]}for j in selected],"actual_tested_tree_from_native_originals_verified":False}
save("source-jobs-page-001.json",rawjobs);save("source-required-run.json",rawrun);metadata=save("existing-two-cost-job-metadata.json",js(identity))
print(json.dumps({"phase":"existing_metadata_ready","metadata":metadata,"observed_from":s["started_at"],"observed_until":s["finished_at"],"jobs":[{"id":j["id"],"name":j["name"],"failed_steps":[{k:t.get(k)for k in("number","name","started_at","completed_at","conclusion")}for t in j["steps"]if t.get("conclusion")=="failure"]}for j in selected]}),flush=True)
endpoint="repos/TrillionniumFoundation/Trillionnium-Chain/actions/jobs/"+str(X64)+"/logs"
argv=[GH,"api","--hostname","github.com","--method","GET",endpoint]
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE")or k in("GIT_CURL_VERBOSE","GH_DEBUG"):del env[k]
env.update(GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1",GIT_TERMINAL_PROMPT="0")
partial=O/"x64-job132415017426.log.partial";err=O/"x64-job132415017426.stderr"
start=now();tick=time.monotonic();deadline=tick+BUDGET;timed=False;capped=None;spawn_error=None;exit_code=None;eof=set();counts={"stdout":0,"stderr":0}
save("request.json",js({"schema":"trnm-single-original-job-log-request-v1","argv":argv,"cwd":"/private/tmp","endpoint":"https://api.github.com/"+endpoint,"method":"GET","single_gh_invocation":True,"redirect_handled_by_official_gh":True,"http_response_headers_not_requested_or_saved":True,"HTTP_status_not_independently_exposed":True,"source":{"run_id":RUN,"job_id":X64,"head_sha":N,"tree_from_run_metadata":run["head_commit"]["tree_id"]},"stdout_cap_bytes":CAP,"stderr_cap_bytes":ERRCAP,"timeout_seconds":BUDGET,"started_at":start,"gh_executable":GH,"gh_canonical_executable":os.path.realpath(GH)}))
with partial.open("xb")as so,err.open("xb")as se:
 try:
  proc=subprocess.Popen(argv,cwd="/private/tmp",env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  sel=selectors.DefaultSelector()
  for name,stream in(("stdout",proc.stdout),("stderr",proc.stderr)):
   os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,name)
  stop=None
  while sel.get_map():
   left=deadline-time.monotonic()
   if left<=0 and stop is None:
    timed=True;stop=time.monotonic()
    try:os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError:pass
   if stop is not None and time.monotonic()-stop>5:
    try:os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   for key,_ in sel.select(min(1,max(.01,left))if stop is None else .1):
    name=key.data;data=os.read(key.fileobj.fileno(),65536)
    if not data:
     eof.add(name);sel.unregister(key.fileobj);key.fileobj.close();continue
    limit=CAP if name=="stdout"else ERRCAP
    room=max(0,limit-counts[name]);chosen=data[:room];(so if name=="stdout"else se).write(chosen);counts[name]+=len(chosen)
    if len(data)>room and stop is None:
     capped=name;stop=time.monotonic()
     try:os.killpg(proc.pid,signal.SIGTERM)
     except ProcessLookupError:pass
  sel.close();exit_code=proc.wait(timeout=5)
 except Exception as e:
  spawn_error=type(e).__name__+": "+str(e)
  if "proc"in locals()and proc.poll()is None:
   try:os.killpg(proc.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   exit_code=proc.wait(timeout=5)
 so.flush();os.fsync(so.fileno());se.flush();os.fsync(se.fileno())
complete=exit_code==0 and not timed and capped is None and spawn_error is None and eof=={"stdout","stderr"}
if complete:
 log=O/"x64-job132415017426.log";os.rename(partial,log)
else:log=partial
raw=rd(log);assert len(raw)==counts["stdout"]
decoded=raw.decode("utf-8",errors="replace");lines=decoded.splitlines()
patterns=("CONFIRMATION_TARGET","AssertionError","Traceback","FAILED","Error:","error:","exit code","failure","failed","artifact")
hits=[]
for n,line in enumerate(lines):
 if any(p.lower()in line.lower()for p in patterns):hits.append({"line":n+1,"text":line[:1500]})
# This is an index into preserved original bytes, not a synthesized causal conclusion.
summary={"schema":"trnm-N-x64-original-cost-job-log-read-v1","started_at":start,"finished_at":now(),"elapsed_seconds":round(time.monotonic()-tick,3),"source_run":RUN,"source_job":X64,"reported_head_sha":N,"reported_head_tree":run["head_commit"]["tree_id"],"run_attempt":run["run_attempt"],"argv":argv,"exit":exit_code,"timed_out":timed,"cap_hit":capped,"spawn_error":spawn_error,"stream_eof":sorted(eof),"complete_according_to_official_gh_exit_and_stream_EOF":complete,"raw_log":fi(log),"stderr":fi(err),"HTTP_status_not_independently_exposed":True,"API_provider_log_digest_available":False,"original_download_attempts":1,"job_metadata":metadata,"matched_line_count":len(hits),"matched_lines":hits[-100:],"artifact_downloads":False,"stage_or_source_or_remote_mutations":False,"CI_reexecuted":False,"four_second_or_worker_assertion_not_inferred_from_job_conclusion":True}
pin=save("summary.json",js(summary))
entries=[fi(p)for p in sorted(O.iterdir())if p.is_file()]
index=save("EVIDENCE_INDEX.json",js({"schema":"trnm-N-cost-log-read-index-v1","files":entries,"self_excluded":"EVIDENCE_INDEX.json"}))
print(json.dumps({"phase":"completed","summary":pin,"index":index,"complete":complete,"exit":exit_code,"raw_log":summary["raw_log"],"hits_tail":hits[-25:]}),flush=True)
