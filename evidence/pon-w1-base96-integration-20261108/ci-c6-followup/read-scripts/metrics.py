from pathlib import Path
import json,zipfile
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
base=OUT/"new-jobs"/"128660701377";fetch=json.loads((base/"artifact-fetch.json").read_text())
with zipfile.ZipFile(fetch["cache_path"]) as z:
 result=json.loads(z.read("results.json"))
 out={"job_id":128660701377,"failure":result["failure"],"expected_resources":result.get("expected_resources"),
 "original_inputs":result.get("original_inputs"),"public_phase_placement":result.get("public_phase_placement"),
 "outer_timeout_seconds":result.get("original_campaign_outer_timeout_seconds"),"attempts":[]}
 for n in (1,2,3):
  report=json.loads(z.read(f"run-{n}-raw/report.json"))
  r={"number":n,"step":result["attempts"][n-1]["step"],"finite_experiment_criteria_met":report["finite_experiment_criteria_met"],
   "public_resource_policy":report.get("public_resource_policy"),"business_blocks":report["preparation"].get("business_blocks"),
   "phases":[]}
  for p in report["phases"]:
   x={k:p.get(k) for k in ["mode","duration_seconds","attacker_processes_requested","attacker_processes_ready","business_started_ns","all_signed_rounds_confirmed_in_window","finite_phase_criteria_met","actor_reports_successful_without_cap_or_kill","observer_complete","receiver_client_state_equal","whole_parent_phase_wall_ns","whole_parent_phase_cpu_ns","genuine_budget_depletion_observed","depletion_at_ns","receiver_and_verifier_setup_wall_ns","receiver_and_verifier_setup_cpu_ns"]}
   x["confirmations"]=[{k:v for k,v in c.items() if not isinstance(v,(dict,list))} for c in p["confirmations"]]
   x["confirmation_nested"]=[{k:(list(v) if isinstance(v,dict) else {"length":len(v)}) for k,v in c.items() if isinstance(v,(dict,list))} for c in p["confirmations"]]
   r["phases"].append(x)
  out["attempts"].append(r)
with (base/"business-metrics.json").open("x") as f:json.dump(out,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps(out),flush=True)
base=OUT/"new-jobs"/"128660701948";fetch=json.loads((base/"artifact-fetch.json").read_text())
with zipfile.ZipFile(fetch["cache_path"]) as z:
 rows=[]
 for label in ("original","fresh"):
  r=json.loads(z.read(f"fresh-service/{label}/report.json"))
  rows.append({"label":label,"finite_target_met":r["finite_target_met"],"phases":[{k:p.get(k) for k in ["mode","workers","requested_window_ns","business_started_ns","confirmation_ended_ns","client_confirmation_latency_ns","client_confirmed_before_original_window_end","client_confirmed_transactions","finite_business_target_met","verification_errors"]} for p in r["phases"]]})
with (base/"business-metrics.json").open("x") as f:json.dump(rows,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps({"job_id":128660701948,"reports":rows}),flush=True)
