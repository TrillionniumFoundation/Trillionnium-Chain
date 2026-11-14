import hashlib,json,os,pathlib,re,subprocess
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1");O=E/"final-entry-and-timing-excerpts-v1";O.mkdir(exist_ok=False)
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
a=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never","cat-file","blob",H+":trillionnium/crates/trnm-pon-node/src/ingress.rs"]
c=subprocess.run(a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);assert c.returncode==0
(O/"ingress.rs.raw").write_bytes(c.stdout);(O/"ingress.rs.stderr").write_bytes(c.stderr)
(O/"source-identity.json").write_text(json.dumps({"path":"trillionnium/crates/trnm-pon-node/src/ingress.rs","head":H,"argv":a,"exit":c.returncode,"bytes":len(c.stdout),"sha256":hashlib.sha256(c.stdout).hexdigest(),"git_oid":hashlib.sha1(b"blob "+str(len(c.stdout)).encode()+b"\0"+c.stdout).hexdigest()},indent=2)+"\n")
lines=c.stdout.decode().splitlines();locs=[i for i,s in enumerate(lines) if "pub fn receive_public_page_from_before" in s or "fn host_for" in s or "require_for_listener" in s]
ranges=[]
for x in locs:
 a=max(0,x-8);b=min(len(lines),x+120)
 if ranges and a<=ranges[-1][1]:ranges[-1][1]=max(ranges[-1][1],b)
 else:ranges.append([a,b])
(O/"ingress-resource-entry.txt").write_text("\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a,b)) for a,b in ranges)+"\n")
def extract(src,name,ranges):
 lines=src.read_text().splitlines();(O/name).write_text("\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,min(b,len(lines)))) for a,b in ranges)+"\n")
extract(E/"kernel-host-contract-v1/trillionnium--crates--trnm-pon-node--src--host_kernel_parent.rs.raw","kernel-optional-loopback.txt",[(618,700),(1525,1583)])
extract(E/"production-host-entry-v1/public-v3.stdout","serve-entry.txt",[(2266,2445)])
extract(E/"source-capture-v1/trillionnium--crates--trnm-pon-node--tests--public_v3_from_zero.rs.raw","fixture-call-and-pressure-constants.txt",[(194,268),(839,869)])
R=json.loads((E/"host-ownership-and-N-results-v1/N-confirmation-phase-extract.json").read_bytes())
out=[]
for r in R:
 phases=[]
 for p in r["phases"]:
  replays=[]
  for x in p["replays"]:
   d={k:x[k] for k in ("history_call_index","replay_started_ns","replay_ended_ns","replay_wall_ns","replay_thread_cpu_ns","replay_accepted","replay_error")}
   o=x["native_import_observation"]
   d["host_checks"]=o.get("host_checks")
   d["phases"]=o.get("phases")
   a=o.get("native_attribution",{})
   d["native_attribution_scalars"]={k:v for k,v in a.items() if v is None or isinstance(v,(bool,str,int,float))} if isinstance(a,dict) else a
   d["native_attribution_shape"]={k:{"type":type(v).__name__,"keys":list(v)[:30] if isinstance(v,dict) else None,"length":len(v) if isinstance(v,list) else None} for k,v in a.items()} if isinstance(a,dict) else None
   h=o.get("host_checkpoint_attribution",{})
   d["host_checkpoint_attribution"]=h
   if p["scalars"]["mode"]=="from-zero-pressure":replays.append(d)
  phases.append({"mode":p["scalars"]["mode"],"business_started_ns":p["scalars"].get("business_started_ns"),"confirmation_ended_ns":p["scalars"].get("confirmation_ended_ns"),"confirmed":p["scalars"].get("client_confirmed_transactions"),"workers":p["scalars"].get("workers"),"window":p["scalars"].get("requested_window_ns"),"submit_count":len(p["honest_submissions"]),"submit_ok":sum(x["status"]=="ok" for x in p["honest_submissions"]),"last_submit_ended_ns":p["honest_submissions"][-1]["ended_ns"] if p["honest_submissions"] else None,"history_count":len(p["honest_history"]),"history_ok":sum(x["status"]=="ok" for x in p["honest_history"]),"replay_count":len(p["replays"]),"replay_accepted":sum(x["replay_accepted"] for x in p["replays"]),"pressure_replays":replays,"verification_errors":p["verification_errors"]})
 out.append({"artifact":r["artifact"],"report_sha256":r["report_sha256"],"phases":phases})
raw=json.dumps(out,indent=2,sort_keys=True).encode()+b"\n";(O/"N-pressure-compact.json").write_bytes(raw)
print(json.dumps({"dir":str(O),"ingress_locations":[i+1 for i in locs],"files":[{"name":p.name,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(O.iterdir())]},sort_keys=True))
