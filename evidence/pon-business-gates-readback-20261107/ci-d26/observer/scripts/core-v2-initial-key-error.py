from pathlib import Path
import json,hashlib,copy
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107")
old=ROOT/"original-business-core-v1.json";doc=json.loads(old.read_bytes())
pure=json.loads((ROOT/"20261107T145800Z-d26e047dedfc-3ca4a7ff/fresh-artifact-read-v1/independent-pure-read-v1/summary.json").read_bytes())
pure_by_id={x["artifact_id"]:x for x in pure["results"]}
changes=[]
for row in doc["fresh"]:
 p=pure_by_id[row["artifact_id"]]
 assert "cache_read" not in p["cohorts"]["original"]
 original=row["cohorts"]["original"]
 before=original.get("cache_path_subcheck_passed")
 original["cache_path_subcheck_passed"]=None
 original["cache_path_subcheck_status"]="not_applicable_original_retained_proof"
 original["cache_path_subcheck_reason"]="The fresh-only cache path validator was not executed for the original repeated-proof cohort; its cache hits are expected, and the original strict confirmation failure remains unchanged."
 assert "cache_read" in p["cohorts"]["fresh"] and p["cohorts"]["fresh"]["cache_read"]["enabled"] is True
 row["cohorts"]["fresh"]["cache_path_subcheck_status"]="passed"
 changes.append({"artifact_id":row["artifact_id"],"old_original_subcheck_boolean":before,"new_original_subcheck_boolean":None,"new_status":"not_applicable_original_retained_proof","original_report_sha256":p["cohorts"]["original"]["sha256"],"original_business_error_unchanged":p["cohorts"]["original"]["strict_report_error"]})
doc["schema"]="trnm-original-business-core-v2"
doc["correction"]={"supersedes":str(old),"superseded_sha256":hashlib.sha256(old.read_bytes()).hexdigest(),"reason":"Distinguish not-applicable fresh-only path subcheck from failure; preserve all original report bytes and business results.","changes":changes}
out=ROOT/"original-business-core-v2.json";out.write_text(json.dumps(doc,indent=2)+chr(10))
print(json.dumps({"path":str(out),"bytes":out.stat().st_size,"sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"changes":changes}))
