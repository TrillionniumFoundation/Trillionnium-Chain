from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import gzip,hashlib,json,os,re,resource,shutil,signal,subprocess,time
SPEC=json.loads("[{\"job_id\":128662229865,\"label\":\"new-jobs/128662229865\",\"kind\":\"executed-failure\"},{\"job_id\":128662229758,\"label\":\"new-jobs/128662229758\",\"kind\":\"executed-failure\"},{\"job_id\":128662229491,\"label\":\"new-jobs/128662229491\",\"kind\":\"executed-failure\"},{\"job_id\":128660701948,\"label\":\"new-jobs/128660701948\",\"kind\":\"executed-failure\"},{\"job_id\":128660701711,\"label\":\"new-jobs/128660701711\",\"kind\":\"executed-failure\"},{\"job_id\":128660701637,\"label\":\"new-jobs/128660701637\",\"kind\":\"executed-failure\"},{\"job_id\":128660701605,\"label\":\"new-jobs/128660701605\",\"kind\":\"executed-failure\"},{\"job_id\":128660701377,\"label\":\"new-jobs/128660701377\",\"kind\":\"executed-failure\"},{\"job_id\":128655993256,\"label\":\"history/replica-1\",\"kind\":\"history-failure\"},{\"job_id\":128655993533,\"label\":\"history/replica-2\",\"kind\":\"history-success\"},{\"job_id\":128662532819,\"label\":\"new-jobs/128662532819\",\"kind\":\"source-guard-sample\"},{\"job_id\":128662229854,\"label\":\"new-jobs/128662229854\",\"kind\":\"source-guard-sample\"},{\"job_id\":128660702010,\"label\":\"new-jobs/128660702010\",\"kind\":\"source-guard-sample\"}]")
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
assert OUT.is_dir()
gh=shutil.which("gh");assert gh
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
def jput(path,d):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("x") as f:json.dump(d,f,sort_keys=True,indent=2);f.write("\n")
def bound():
 resource.setrlimit(resource.RLIMIT_FSIZE,(24*1024*1024,24*1024*1024))
def fetch(s):
 out=OUT/s["label"];out.mkdir(parents=True,exist_ok=True)
 raw=out/"job.log";err=out/"log.stderr"
 argv=[gh,"api",f"repos/TrillionniumFoundation/Trillionnium-Chain/actions/jobs/{s['job_id']}/logs"]
 started=time.time_ns();timed_out=False;exception=None
 with raw.open("xb") as of,err.open("xb") as ef:
  try:p=subprocess.run(argv,stdout=of,stderr=ef,timeout=75,preexec_fn=bound);rc=p.returncode
  except subprocess.TimeoutExpired:rc=None;timed_out=True
  except Exception as e:rc=None;exception=repr(e)
 meta=dict(s,argv=argv,started_unix_ns=started,finished_unix_ns=time.time_ns(),
  exit_code=rc,timed_out=timed_out,exception=exception,per_stream_byte_cap=24*1024*1024,
  raw={"path":str(raw.relative_to(OUT)),"bytes":raw.stat().st_size,"sha256":sha(raw)},
  stderr={"path":str(err.relative_to(OUT)),"bytes":err.stat().st_size,"sha256":sha(err)},
  complete_download=rc==0 and not timed_out)
 jput(out/"log.fetch.json",meta)
 data=raw.read_bytes().decode("utf-8",errors="replace");lines=data.splitlines()
 pattern=re.compile(r"##\[error\]|panicked at|Error:|error:|FAILED|FAIL:|Traceback|AssertionError|ValueError|timed out|deadline|finite_completion|business_success|protocol_success|confirmations|summary",re.I)
 matches=[{"line":i+1,"text":t[:1800]} for i,t in enumerate(lines) if pattern.search(t)]
 analysis={"job_id":s["job_id"],"kind":s["kind"],"log_sha256":meta["raw"]["sha256"],"log_lines":len(lines),
  "complete_download":meta["complete_download"],"candidate_count":len(matches),
  "first_candidates":matches[:12],"last_candidates":matches[-32:],
  "tail":[{"line":i+1,"text":t[:1800]} for i,t in enumerate(lines) if i>=max(0,len(lines)-24)],
  "note":"Pattern hits are navigation only; expected refusal controls can match; not inferred failure causes."}
 jput(out/"log-navigation.json",analysis)
 print(json.dumps(meta,sort_keys=True),flush=True)
 return meta
records=[]
with ThreadPoolExecutor(max_workers=3) as pool:
 for f in as_completed([pool.submit(fetch,s) for s in SPEC]):records.append(f.result())
jput(OUT/"log-fetch-manifest.json",{"schema":"TRNM-W1-C6-LATER-LOG-READ1","requests":records,
 "GET_count":len(records),"read_only":True,"reruns":0,"dispatches":0,"source_changes":0})
print(json.dumps({"finished":True,"files":len(records),"failures":[r for r in records if not r["complete_download"]],
 "total_log_bytes":sum(r["raw"]["bytes"] for r in records)}),flush=True)
