import json,pathlib,hashlib
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1")
R=json.loads((E/"host-ownership-and-N-results-v1/N-confirmation-phase-extract.json").read_bytes())
def slim(x,depth=0):
 if x is None or isinstance(x,(bool,int,float,str)):return x
 if isinstance(x,list):
  if len(x)<=16 and depth<3:return [slim(v,depth+1) for v in x]
  return {"type":"list","count":len(x),"first_keys":list(x[0]) if x and isinstance(x[0],dict) else None}
 if isinstance(x,dict):
  return {k:(slim(v,depth+1) if depth<3 else {"type":type(v).__name__,"count":len(v)}) if isinstance(v,(dict,list)) else v for k,v in x.items()}
 return type(x).__name__
out=[]
for r in R:
 phases=[]
 for p in r["phases"]:
  x={"mode":p["scalars"]["mode"],"business_started_ns":p["scalars"].get("business_started_ns"),"confirmation_ended_ns":p["scalars"].get("confirmation_ended_ns"),"workers":p["scalars"].get("workers"),"window_ns":p["scalars"].get("requested_window_ns"),"confirmed":p["scalars"].get("client_confirmed_transactions"),"submit_count":len(p["honest_submissions"]),"submit_ok":sum(s["status"]=="ok" for s in p["honest_submissions"]),"last_submit_end_ns":p["honest_submissions"][-1]["ended_ns"],"history_count":len(p["honest_history"]),"history_ok":sum(s["status"]=="ok" for s in p["honest_history"]),"replay_count":len(p["replays"]),"replay_accepted":sum(s["replay_accepted"] for s in p["replays"])}
  if p["scalars"]["mode"]=="from-zero-pressure":
   x["replays"]=[]
   for rp in p["replays"]:
    o=rp["native_import_observation"]
    x["replays"].append({**{k:rp[k] for k in ("replay_started_ns","replay_ended_ns","replay_wall_ns","replay_thread_cpu_ns","replay_accepted","replay_error")},"host_checks":slim(o.get("host_checks")),"phases":slim(o.get("phases")),"native_attribution":slim(o.get("native_attribution")),"host_attribution":slim(o.get("host_checkpoint_attribution"))})
  phases.append(x)
 out.append({"artifact":r["artifact"],"report_sha256":r["report_sha256"],"phases":phases})
p=E/"bounded-N-phase-timing-v1.json";raw=json.dumps(out,indent=2,sort_keys=True).encode()+b"\n";p.write_bytes(raw)
print(json.dumps({"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"extract":out},sort_keys=True))
