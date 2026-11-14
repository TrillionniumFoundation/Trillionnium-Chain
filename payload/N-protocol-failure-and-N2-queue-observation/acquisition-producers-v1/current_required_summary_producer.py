import hashlib,json,pathlib
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1");D=R/"current-required-status-v1";D.mkdir(mode=0o700)
p1=json.loads((R/"current-head-and-artifacts-GET-v1"/"current-head-check-runs.stdout").read_bytes())
p2=json.loads((R/"required-pagination-GET-v1"/"N2-check-runs-page2.stdout").read_bytes())
req=json.loads((R/"initial-GET-v1"/"main-required-status-checks.stdout").read_bytes())
run=json.loads((R/"required-pagination-GET-v1"/"N2-required-workflow-run.stdout").read_bytes())
jobs=json.loads((R/"required-pagination-GET-v1"/"N2-required-workflow-jobs.stdout").read_bytes())
nj=json.loads((R/"required-pagination-GET-v1"/"N-required-workflow-jobs.stdout").read_bytes())
checks=p1["check_runs"]+p2["check_runs"]
assert p1["total_count"]==p2["total_count"]==146 and len(checks)==146 and len({x["id"] for x in checks})==146
assert jobs["total_count"]==len(jobs["jobs"])==0
assert nj["total_count"]==len(nj["jobs"])<100
required=[]
for wanted in req["checks"]:
 observed=[{k:c.get(k) for k in ["id","name","head_sha","status","conclusion","details_url","started_at","completed_at"]}|{"app_id":c.get("app",{}).get("id")} for c in checks if c["name"]==wanted["context"] and c.get("app",{}).get("id")==wanted["app_id"]]
 required.append({"context":wanted["context"],"required_app_id":wanted["app_id"],"observed_checks":observed,"observed_state":"ABSENT_FOR_CURRENT_HEAD" if not observed else "PRESENT"})
out={"schema":"trnm-N2-current-required-status-exact-observation-v1","head":"096c6b5f9b952c49389fd975515744074ba61317","required_strict":req["strict"],"check_pages":2,"checks_observed":146,"all_check_pages_complete":True,"required":required,"N2_required_workflow":{k:run.get(k) for k in ["id","head_sha","status","conclusion","created_at","updated_at","event","path","run_attempt","html_url"]},"N2_required_job_count":0,"N_run_jobs":[{k:j.get(k) for k in ["id","name","status","conclusion","started_at","completed_at","head_sha"]} for j in nj["jobs"]],"N_job_page_complete":True,"separate_current_and_historical_heads":True,"no_ci_success_inferred_from_absence":True}
raw=(json.dumps(out,sort_keys=True,indent=2)+"\n").encode()
with (D/"summary.json").open("xb") as f:f.write(raw)
print(json.dumps(out,sort_keys=True))
