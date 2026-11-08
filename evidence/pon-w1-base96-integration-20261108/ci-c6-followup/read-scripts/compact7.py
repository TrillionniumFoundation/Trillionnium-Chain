from pathlib import Path
import json
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
rows=[]
for jid in [128662229865,128662229758,128662229491,128660701711,128660701605,128660701948,128660701637]:
 d=json.loads((OUT/"new-jobs"/str(jid)/"business-readback.json").read_text())
 if "confirmation_observation" in d:
  r={"job_id":jid,"failures":d["failures"],"native_all_passed":d["all_named_tests_passed"],
   "raw_finite_target_met":d["raw_finite_target_met"],"native_execution_completed":d["terminal"]["native_execution_completed"],
   "phases":[{"mode":p["mode"],"workers":p["workers"],"window_ns":p["window_ns"],
    "business":p["business"],"clock":{k:v for k,v in p["request_clock"].items() if not isinstance(v,(dict,list))},
    "verification_errors":p["verification_errors"]} for p in d["confirmation_observation"]["phases"]]}
 elif jid==128660701948:
  r={"job_id":jid,"manifest":d["manifest"],"original_log":d["original_log"],"fresh_log":d["fresh_log"]}
 else:r=d
 rows.append(r)
with (OUT/"business-readback-compact-first7.json").open("x") as f:json.dump(rows,f,sort_keys=True,indent=2);f.write("\n")
for r in rows:print(json.dumps(r),flush=True)
