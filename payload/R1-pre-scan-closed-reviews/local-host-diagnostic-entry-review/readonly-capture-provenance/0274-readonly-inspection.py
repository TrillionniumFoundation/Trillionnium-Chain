import hashlib,json,os,pathlib,subprocess
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1");O=E/"production-host-entry-v1";O.mkdir(exist_ok=False)
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
def git(name,args):
 a=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never",*args]
 c=subprocess.run(a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 (O/(name+".stdout")).write_bytes(c.stdout);(O/(name+".stderr")).write_bytes(c.stderr)
 (O/(name+".command.json")).write_text(json.dumps({"argv":a,"exit":c.returncode,"stdout_sha256":hashlib.sha256(c.stdout).hexdigest()},indent=2)+"\n")
 assert c.returncode==0,(name,c.returncode)
 return c.stdout
loc=git("host-locations",["grep","-n","-e","trnmponpublic.slice",H,"--","trillionnium/crates/trnm-pon-node/src"])
raw=git("public-v3",["cat-file","blob",H+":trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"])
assert hashlib.sha256(raw).hexdigest()=="0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a"
lines=raw.decode().splitlines()
(O/"public-v3-entry-excerpts.txt").write_text("\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,b)) for a,b in [(1,160),(770,900)])+"\n")
R=json.loads((E/"host-ownership-and-N-results-v1/N-confirmation-phase-extract.json").read_bytes())
out=[]
for r in R:
 phases=[]
 for p in r["phases"]:
  replays=[]
  for x in p["replays"]:
   o=x.get("native_import_observation",{})
   row={k:x[k] for k in ("history_call_index","replay_started_ns","replay_ended_ns","replay_wall_ns","replay_thread_cpu_ns","replay_accepted","replay_error")}
   row["observation_summary"]={k:v for k,v in o.items() if k not in ("packets","phases","host_checks")}
   row["phase_data"]=o.get("phases")
   row["host_checks_type"]=type(o.get("host_checks")).__name__
   row["host_checks_sample"]=o.get("host_checks") if not isinstance(o.get("host_checks"),list) else o.get("host_checks")[:2]
   row["packet_count"]=len(o.get("packets",[]))
   replays.append(row)
  phases.append({"mode":p["scalars"].get("mode"),"requested_window_ns":p["scalars"].get("requested_window_ns"),"workers":p["scalars"].get("workers"),"business_started_ns":p["scalars"].get("business_started_ns"),"confirmation_ended_ns":p["scalars"].get("confirmation_ended_ns"),"replay_total_wall_ns":p["scalars"].get("independent_replay_and_confirmation_wall_ns"),"replay_total_cpu_ns":p["scalars"].get("independent_replay_and_confirmation_cpu_ns"),"submission_count":len(p["honest_submissions"]),"submission_ok_count":sum(x["status"]=="ok" for x in p["honest_submissions"]),"history_count":len(p["honest_history"]),"history_ok_count":sum(x["status"]=="ok" for x in p["honest_history"]),"replays":replays,"initial_meter":p["initial_meter"],"final_meter":p["final_meter"],"service":p["service"]})
 out.append({"artifact":r["artifact"],"report_sha256":r["report_sha256"],"phases":phases})
raw=json.dumps(out,indent=2,sort_keys=True).encode()+b"\n";(O/"N-timing-and-import-phases.json").write_bytes(raw)
print(json.dumps({"dir":str(O),"host_locations":loc.decode(),"timing_extract_bytes":len(raw),"timing_extract_sha256":hashlib.sha256(raw).hexdigest()},sort_keys=True))
