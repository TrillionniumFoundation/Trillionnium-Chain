import json,hashlib,collections,os,sys
from pathlib import Path
D=Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1")
O=Path("/private/tmp/chain-R1-nonhost-performance-review-20261114-v1/stage-evidence-v1")
O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
p=D/"critical-path-summary-v2/client-server-compact.json"
raw=p.read_bytes()
if hashlib.sha256(raw).hexdigest()!="74a49317aba30ba6059dddde27de4c5fcbc452ce7ad419964599ad9c353de418":raise RuntimeError("input_sha")
x=json.loads(raw)
out=[]
fields=("construction_ns","challenge_ns","solution_search_ns","solution_search_thread_cpu_ns","solution_body_response_ns","total_elapsed_ns")
def stats(v):
 v=[z for z in v if type(z) is int]
 return {"n":len(v),"sum":sum(v),"min":min(v) if v else None,"max":max(v) if v else None}
for phase in x["phases"]:
 cats=collections.defaultdict(list)
 for row in phase["rows"]: cats[row["category"]].append(row)
 row={"kind":phase["kind"],"member":phase["member"],"phase":phase["phase"],"mode":phase["mode"],"report_sha256":phase["report_sha256"],"categories":[]}
 for cat,rows in cats.items():
  q={"category":cat,"records":len(rows),"source_pointers":[r["client_pointer"] for r in rows],
  "client_span_ns":{"start":min(r["started_ns"] for r in rows),"end":max(r["ended_ns"] for r in rows)},
  "client_thread_cpu_ns":stats(r.get("client_thread_cpu_ns") for r in rows),
  "dispatch_thread_cpu_ns":stats(r.get("dispatch_thread_cpu_ns") for r in rows),
  "client_metrics":{k:stats(r.get("client_metrics",{}).get(k) for r in rows) for k in fields},
  "server_waits":{k:stats((r.get(k) or {}).get("wall_ns") for r in rows) for k in ("challenge_wait","grant_wait","paid_task_queue_wait","response_write")},
  "server_phases":{}}
  pk=sorted({p["phase"] for r in rows for p in r.get("phases",[])})
  for k in pk:
   vals=[p for r in rows for p in r.get("phases",[]) if p["phase"]==k]
   q["server_phases"][k]={f:stats(p.get(f) for p in vals) for f in ("wall_ns","thread_cpu_ns")}
  row["categories"].append(q)
 out.append(row)
v={"schema":"trnm-r1-existing-matched-client-stage-summary-v1","source":{"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"scope":"Sums are only same named field across disjoint matched requests; stages are nested and MUST NOT be summed together or across clock domains. No new measurement or test.","phases":out}
data=(json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
(O/"matched-stage-aggregates.json").write_bytes(data)
view=[]
for phase in out:
 for c in phase["categories"]:
  view.append({"kind":phase["kind"],"variant":phase["member"].split("/")[1],"phase":phase["phase"],"category":c["category"],"n":c["records"],
   "client_span_ms":{k:round(v/1e6,3) for k,v in c["client_span_ns"].items()},
   "client_cpu_ms":round(c["client_thread_cpu_ns"]["sum"]/1e6,3),
   "construction_ms":round(c["client_metrics"]["construction_ns"]["sum"]/1e6,3),
   "challenge_ms":round(c["client_metrics"]["challenge_ns"]["sum"]/1e6,3),
   "solution_body_response_ms":round(c["client_metrics"]["solution_body_response_ns"]["sum"]/1e6,3),
   "queue_ms":round(c["server_waits"]["paid_task_queue_wait"]["sum"]/1e6,3),
   "server_phase_ms":{k:{"wall":round(v["wall_ns"]["sum"]/1e6,3),"cpu":round(v["thread_cpu_ns"]["sum"]/1e6,3)} for k,v in c["server_phases"].items()}})
(O/"small-table.json").write_text(json.dumps(view,indent=2,sort_keys=True)+"\n")
print(json.dumps({"path":str(O/"matched-stage-aggregates.json"),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"table":view},sort_keys=True))
