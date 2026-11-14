import hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1");D=R/"actual-guard-and-acceptance-v1"
facts=json.loads((D/"actual-original-ACK-and-gate-facts.json").read_bytes())
out=[]
for f in facts:
 phases=[]
 for p in f["phases"]:
  subs=p["honest_submission_records"]
  phases.append({"mode":p["mode"],"submission_count":len(subs),"ack_count":sum(x.get("status")=="ok" and x.get("response",{}).get("ok") is True and x.get("error") is None for x in subs),"ack_before_window_count":sum(x.get("status")=="ok" and x.get("response",{}).get("ok") is True and x.get("returned_after_window") is False for x in subs),"submission_returned_after_deadline_count":sum(x.get("returned_after_deadline") is True for x in subs),"submission_ends_ns":[x.get("ended_ns") for x in subs],"verification_errors":p["verification_errors"],"final_confirmation_stage_present":p["independent_final_confirmation_stage"] is not None})
 out.append({"artifact_id":f["artifact_id"],"native_runs":f["native_runs"],"phases":phases,"original_confirmation_observation_flags":{"original_gate_validated":f["confirmation_observation"].get("original_gate_validated"),"original_gate_validation_error":f["confirmation_observation"].get("original_gate_validation_error")}})
raw=(json.dumps(out,sort_keys=True,indent=2)+"\n").encode()
with (D/"compact-ACK-gate-summary.json").open("xb") as h:h.write(raw)
src=R/"protocol-source-comparison-v1"/"scripts--ci--run_from_zero_native.py.2aba481576bc5a09a2d546e467e1b19d6e9de7bd.raw"
rg=shutil.which("rg",path="/opt/homebrew/bin:/usr/bin:/bin")
p=subprocess.run([rg,"--line-number","--context","12","finite_business_target_met|requested_window_ns.*4000000000|workers.*16",str(src)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
with (D/"actual-phase-target-guard.stdout").open("xb") as h:h.write(p.stdout)
with (D/"actual-phase-target-guard.stderr").open("xb") as h:h.write(p.stderr)
print(json.dumps(out,sort_keys=True));print(p.stdout.decode())
