import os,sys,json,hashlib,pathlib,subprocess,stat
D=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1")
O=D/"critical-path-summary-v2";O.mkdir(exist_ok=False)
def read(p,sha,cap):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=cap
  with os.fdopen(fd,"rb",closefd=False) as f:b=f.read(cap+1)
  en=os.fstat(fd);pa=os.lstat(p)
  assert (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(en.st_dev,en.st_ino,en.st_size,en.st_mtime_ns,en.st_ctime_ns)==(pa.st_dev,pa.st_ino,pa.st_size,pa.st_mtime_ns,pa.st_ctime_ns)
  assert hashlib.sha256(b).hexdigest()==sha
  return b
 finally:os.close(fd)
p=D/"artifact-readback-v1/client-server-stage-binding.json"
raw=read(p,"af149f8dee0bb7ec37456775cf67421dd9e7ade5248594e6a0d80d400745cb24",2*1024*1024)
data=json.loads(raw);out=[]
for phase in data["phases"]:
 rows=[]
 for row in phase["rows"]:
  c,s=row["client"],row["server"]
  phases=[{"phase":q["phase"],"wall_ns":q["wall_ns"],"thread_cpu_ns":q["thread_cpu_ns"],"error_code":q.get("error_code")} for q in s["submit_phases"] if q["started"]]
  rows.append({"category":row["category"],"index":row["call_index"],"client_pointer":row["client_pointer"],"server_pointer":row["server_pointer"],"connection":s["connection_id"],"started_ns":c["started_ns"],"ended_ns":c["ended_ns"],"client_thread_cpu_ns":c["client_thread_cpu_ns"],"client_metrics":c["metrics"],"server_lifecycle":s["lifecycle"],"observer_epoch_offset_ns":row["observer_epoch_offset_ns"],"challenge_wait":s["challenge_wait"],"grant_wait":s["grant_wait"],"paid_task_queue_wait":s["paid_task_queue_wait"],"dispatch_thread_cpu_ns":s["dispatch_thread_cpu_ns"],"phases":phases,"response_write":s["response_write"]})
 out.append({k:phase[k] for k in ["kind","member","report_sha256","phase","mode"]}|{"rows":rows})
b=(json.dumps({"source":{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"scope":"Derived exact matched original request spans. Wall intervals may be nested or overlap; no summed total CPU attribution is claimed.","phases":out},indent=2,sort_keys=True)+"\n").encode()
(O/"client-server-compact.json").write_bytes(b)
print(json.dumps({"path":str(O/"client-server-compact.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}))
for pp in out:
 if pp["phase"]!=1:continue
 ss=[x for x in pp["rows"] if x["category"]=="honest_submissions"];hh=[x for x in pp["rows"] if x["category"]=="honest_history"]
 def compact(r):
  ph={q["phase"]:q for q in r["phases"]}
  ms=lambda n:round(n/1e6,3)
  return {"i":r["index"],"start_ms":ms(r["started_ns"]),"end_ms":ms(r["ended_ns"]),"challenge_ms":ms(r["client_metrics"]["challenge_ns"]),"solve_ms":ms(r["client_metrics"]["solution_search_ns"]),"client_body_response_ms":ms(r["client_metrics"]["solution_body_response_ns"]),"grant_ms":ms(r["grant_wait"]["wall_ns"]),"queue_ms":ms(r["paid_task_queue_wait"]["wall_ns"]),"wall_phases_ms":{k:ms(q["wall_ns"]) for k,q in ph.items() if q["wall_ns"]>=1000000},"owner_wait_ms":{k:ms(q["wall_ns"]) for k,q in ph.items() if "owner_wait" in k},"dispatch_cpu_ms":ms(r["dispatch_thread_cpu_ns"])}
 print(json.dumps({"kind":pp["kind"],"member":pp["member"],"submits":[compact(x) for x in ss],"history":[compact(x) for x in hh]},sort_keys=True))
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
cmd=["/usr/bin/git","--git-dir=/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git","grep","-n","-E",r"(struct WorkCheckedPacket|impl WorkCheckedPacket|fn verify_with_progress|enum VerificationProgress|fn verify_full|FullLimb)","2a86462a1ab20c68151719ba4635e3c294391e64","--","trillionnium/crates/trnm-pon-node/src","trillionnium/crates/trnm-crypto-primitives/src","trillionnium/crates/trnm-protocol/src"]
r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40);assert r.returncode==0 and len(r.stdout)<65536
(O/"immutable-w1-symbols.stdout").write_bytes(r.stdout);(O/"immutable-w1-symbols.stderr").write_bytes(r.stderr)
(O/"producer.py").write_text(sys.argv[1])
print(json.dumps({"git_readonly_argv":cmd,"exit":r.returncode,"stdout":r.stdout.decode(),"sha256":hashlib.sha256(r.stdout).hexdigest()}))
