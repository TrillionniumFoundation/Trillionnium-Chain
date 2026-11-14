import datetime,hashlib,json,os,pathlib,re,stat,sys
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-log-source-binding-v1")
BASE=E.parent/"R1-W1-failure-raw-logs-v2"
os.umask(0o077);E.mkdir(mode=0o700,exist_ok=False)
inputs=[(132475259337,"head",215469,"8a8308148cc4584b222a1ad4b89f9ed3b9315e10fc4a3f9b41804d4113692a2c"),(132475258996,"prospective-merge",216283,"d8f8acf7d7e83ff24212cc5b2ce9f09a6817f40910b38d7f25750ed148165002")]
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4";MERGE="a7ee9542d10e15bba4256de9579a0196ba9ab9c9";MAIN="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
results=[]
for job,kind,size,digest in inputs:
 p=BASE/("job-"+str(job)+"-original-log.stdout")
 before=p.stat();raw=p.read_bytes();assert p.stat()==before and len(raw)==size and sha(raw)==digest
 lines=raw.decode().splitlines()
 clean="\n".join(re.sub(r"^\d{4}-\d{2}-\d{2}T\S+Z\s?","",x) for x in lines)
 values=[]
 for m in re.finditer(r"(?m)^[ \t]*\{",clean):
  try:v=json.JSONDecoder().raw_decode(clean[m.start():].lstrip())[0]
  except (ValueError,json.JSONDecodeError):continue
  if type(v)is dict:values.append({"line":clean[:m.start()].count("\n")+1,"value":v})
 sources=[x for x in values if x["value"].get("schema")=="trnm-ci-source-v1"]
 host=[x for x in values if x["value"].get("schema")=="trnm-ci-original-public-host-controller-v2"]
 expected=HEAD if kind=="head" else MERGE
 assert len(sources)==2 and sources[0]["value"]==sources[1]["value"],"two full source objects match"
 s=sources[0]["value"]
 assert s["kind"]==kind and s["candidate"]==HEAD and s["tested_commit"]==expected and s["tested_tree"]==TREE and s["tracked_worktree_verified"]is True and s["tests_executed_by_identity_check"]is False
 assert s["base"]==(None if kind=="head" else MAIN) and s["prospective_merge"]==(None if kind=="head" else MERGE)
 assert len(host)==1
 h=host[0]["value"];assert h["preparation"]["completed"]is True and h["preparation"]["process"]["exit_code"]==0
 artlines=[x for x in lines if "Artifact ID" in x or "digest of uploaded artifact" in x or "With the provided path" in x or "Artifact download URL:" in x]
 sourcepin=put(E/("job-"+str(job)+"-source-before-after.json"),(json.dumps({"source":str(p),"source_sha256":digest,"observed_kind":kind,"source_values":sources},indent=2,sort_keys=True)+"\n").encode())
 hostpin=put(E/("job-"+str(job)+"-actual-host-controller.json"),(json.dumps(host[0],indent=2,sort_keys=True)+"\n").encode())
 results.append({"job_id":job,"kind":kind,"log":{"path":str(p),"bytes":size,"sha256":digest},"source_before_after":sourcepin,"host_controller":hostpin,"source":s,"host_outer":{"failure":h["failure"],"final_host_errors":h["final_host_errors"],"systemd_run_exit":h["systemd_run_exit"],"passed":h["passed"],"build_exit":h["preparation"]["process"]["exit_code"],"build_wall_ns":h["preparation"]["process"]["wall_ns"]},"artifact_log_lines":artlines})
summary={"schema":"trnm-R1-W1-full-log-source-and-host-review-v1","results":results,"limited_initial_parser_retained":"v2 extraction selected only same-line source JSON; this overlay parses full timestamp-stripped JSON blocks; original logs unchanged","actual_inner_service_failure":"UNKNOWN_PENDING_ARTIFACT","native_or_remote_mutation":False}
pin=put(E/"summary.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
put(E/"producer.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
print(json.dumps({"summary":pin,"jobs":[{"job":x["job_id"],"source":x["source"],"outer":x["host_outer"],"artifacts":x["artifact_log_lines"]} for x in results]},sort_keys=True),flush=True)
