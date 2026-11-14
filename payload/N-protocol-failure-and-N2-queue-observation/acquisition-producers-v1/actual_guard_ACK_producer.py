import hashlib,json,pathlib,re,shutil,subprocess,zipfile
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=R/"actual-guard-and-acceptance-v1";D.mkdir(mode=0o700)
source=R/"protocol-source-comparison-v1"/"scripts--ci--run_from_zero_native.py.2aba481576bc5a09a2d546e467e1b19d6e9de7bd.raw"
rg=shutil.which("rg",path="/opt/homebrew/bin:/usr/bin:/bin");assert rg
p=subprocess.run([rg,"--line-number","--context","18","CONFIRMATION_TARGET|def confirmation_report",str(source)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
with (D/"actual-confirmation-guard.stdout").open("xb") as f:f.write(p.stdout)
with (D/"actual-confirmation-guard.stderr").open("xb") as f:f.write(p.stderr)
patch=(R/"protocol-source-comparison-v1"/"N-to-R1-selected-protocol.patch").read_text()
ci="diff --git"+patch.split("diff --git")[1]
assert ci.startswith("diff --git a/scripts/ci/ci_job.sh ")
with (D/"N-to-R1-ci-job-only.patch").open("xb") as f:f.write(ci.encode())
facts=[]
for ident in [14111407094,14111816359]:
 base=R/"inner-originals-v1"/str(ident)
 m=json.loads((base/"from-zero-native/manifest.json").read_bytes())
 with zipfile.ZipFile(R/"official-complete-artifacts-v1"/(str(ident)+".zip")) as z:report=json.loads(z.read("from-zero-native/confirmation/report.json"))
 phases=[]
 for i,phase in enumerate(report["phases"]):
  subs=phase["honest_submissions"]
  phases.append({"index":i,"mode":phase["mode"],"honest_submission_records":subs,"history_record_primitive_fields":[{k:v for k,v in row.items() if not isinstance(v,(dict,list))} for row in phase["honest_history"]],"verification_errors":phase["verification_errors"],"independent_client_confirmation":phase["independent_client_confirmation"],"independent_final_confirmation_stage":phase["independent_final_confirmation_stage"]})
 small={"artifact_id":ident,"source_before":m.get("source_before"),"source_after":m.get("source_after"),"format_passed":m["format_passed"],"all_named_tests_passed":m["all_named_tests_passed"],"native_runs":[{"name":x["name"],"passed":x["passed"],"exit_code":x["process"]["exit_code"],"timed_out":x["process"]["timed_out"],"named_execution":x.get("named_execution")} for x in m["runs"]],"confirmation_observation":m.get("confirmation_observation"),"phases":phases}
 facts.append(small)
raw=(json.dumps(facts,sort_keys=True,indent=2)+"\n").encode()
with (D/"actual-original-ACK-and-gate-facts.json").open("xb") as f:f.write(raw)
print(json.dumps({"directory":str(D),"guard_exit":p.returncode,"guard_bytes":len(p.stdout),"facts_bytes":len(raw),"facts_sha256":hashlib.sha256(raw).hexdigest()},sort_keys=True))
print(p.stdout.decode())
print(ci)
for f in facts:
 print(json.dumps({"artifact_id":f["artifact_id"],"native_runs":f["native_runs"],"phase_submission_records":[{"mode":x["mode"],"submissions":x["honest_submission_records"],"verification_errors":x["verification_errors"],"final_stage":x["independent_final_confirmation_stage"]} for x in f["phases"]]},sort_keys=True))
