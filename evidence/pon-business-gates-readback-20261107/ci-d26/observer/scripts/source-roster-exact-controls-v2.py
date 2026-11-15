from pathlib import Path
import json,hashlib,collections
D=Path("/home/qian-qi/throughput-ci-observation-20261107/20261107T155220Z-d26e047dedfc-bb63e773")
old=D/"final-native-source-stage-roster-v1.json";v=json.loads(old.read_bytes())
before={"Verify source and original project boundary","Reserve observations and verify ordered source identity","Reserve records and verify ordered source identity"}
after={"Reverify exact unchanged source","Verify measured source after execution","Verify observed source after execution"}
materialize="Reproduce the frozen integration-push source";retain="Preserve this lane's actual push source context"
rows=[]
for r in v["rows"]:
 selected=[s for s in r["source_steps"] if s["name"] in before|after|{materialize,retain}]
 assert len(selected)==4 and all(s["conclusion"]=="success" for s in selected)
 assert sum(s["name"] in before for s in selected)==1 and sum(s["name"] in after for s in selected)==1
 rows.append({"job_id":r["job_id"],"run_id":r["run_id"],"name":r["name"],"original_job_conclusion":r["job_conclusion"],"source_controls":selected})
out={"schema":"trnm-d26-final-native-source-stage-roster-v2","head":v["head"],"metadata_finished_utc":v["metadata_finished_utc"],"native_lane_denominator":34,"source_controls_per_lane":4,"observed_source_controls":sum(len(r["source_controls"]) for r in rows),"source_controls_passed":136,"native_business_gate_validated":False,"supersedes_broad_name_selection":{"path":str(old),"sha256":hashlib.sha256(old.read_bytes()).hexdigest(),"reason":"Exact source-control names; resources substring and campaign-specific source-preserving migration are not source guards."},"rows":rows}
p=D/"final-native-source-stage-roster-v2.json";p.write_text(json.dumps(out,indent=2)+chr(10));print(json.dumps({"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"native_lanes":34,"source_controls_passed":136}))
