import hashlib,json,pathlib
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1");D=R/"current-head-and-artifacts-GET-v1"
checks=json.loads((D/"current-head-check-runs.stdout").read_bytes());runs=json.loads((D/"current-head-workflow-runs.stdout").read_bytes());status=json.loads((D/"current-head-legacy-status.stdout").read_bytes());arts=json.loads((D/"N-run-original-artifacts.stdout").read_bytes());pr=json.loads((D/"pr847-readback.stdout").read_bytes());req=json.loads((R/"initial-GET-v1"/"main-required-status-checks.stdout").read_bytes())
names=set(req.get("contexts",[]))|{x["context"] for x in req.get("checks",[])}
rows=[{k:c.get(k) for k in ["id","name","status","conclusion","head_sha","started_at","completed_at","details_url"]}|{"app_id":c.get("app",{}).get("id")} for c in checks["check_runs"] if c["name"] in names]
allnames=[{"id":c["id"],"name":c["name"],"status":c["status"],"conclusion":c["conclusion"],"details_url":c.get("details_url")} for c in checks["check_runs"]]
selected_runs=[{k:r.get(k) for k in ["id","head_sha","event","status","conclusion","path","created_at","updated_at","html_url"]} for r in runs["workflow_runs"] if r.get("path")==".github/workflows/trnm-required-baseline.yml"]
artsel=[a for a in arts["artifacts"] if a["id"] in [14111407094,14111816359]]
out={"pr_head":pr["head"]["sha"],"pr_stable_since_initial":pr["head"]["sha"]==json.loads((R/"initial-GET-v1"/"pr847.stdout").read_bytes())["head"]["sha"],"required_config":req,"check_count":checks["total_count"],"check_page_count":len(checks["check_runs"]),"required_matching_checks":rows,"all_current_check_names":allnames,"legacy_status":{"state":status["state"],"total_count":status["total_count"],"statuses":status["statuses"]},"workflow_count":runs["total_count"],"workflow_page_count":len(runs["workflow_runs"]),"required_workflow_runs":selected_runs,"N_artifact_count":arts["total_count"],"N_artifact_page_count":len(arts["artifacts"]),"selected_artifacts":artsel}
with (R/"initial-cause-extract-v1"/"current-head-required-and-artifacts.json").open("xb") as f:f.write((json.dumps(out,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(out,sort_keys=True))
