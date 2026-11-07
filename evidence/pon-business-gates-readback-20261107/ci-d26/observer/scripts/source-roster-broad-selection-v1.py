from pathlib import Path
import json,collections,hashlib,sys
R=Path("/home/qian-qi/throughput-ci-observation-20261107")
D=R/"20261107T155220Z-d26e047dedfc-bb63e773"
sys.path.insert(0,str(R));from read_ci_metadata import parse_http
s=json.loads((D/"snapshot.json").read_bytes());jobs=[]
for q in s["queries"]:
 if "/jobs?filter=all" in q["endpoint"]:
  _,_,o=parse_http((D/q["http_file"]).read_bytes());jobs+=o["jobs"]
native=[j for j in jobs if j["name"].startswith(("W1 ","native priorities ("))]
assert len(native)==34
rows=[];counts=collections.Counter()
for j in native:
 steps=[{k:x.get(k) for k in ("name","status","conclusion","started_at","completed_at")} for x in j["steps"] if "source" in x["name"].lower() and "toolchain" not in x["name"].lower()]
 for x in steps:counts[(x["name"],x["conclusion"])]+=1
 rows.append({"job_id":j["id"],"run_id":j["run_id"],"name":j["name"],"job_conclusion":j["conclusion"],"source_steps":steps})
out={"schema":"trnm-d26-final-native-source-stage-roster-v1","metadata_finished_utc":s["finished_utc"],"head":"d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89","native_lane_denominator":34,"whole_job_denominator":37,"whole_job_counts":dict(collections.Counter(j["conclusion"] for j in jobs)),"rows":rows,"native_gate_validated":False}
p=D/"final-native-source-stage-roster-v1.json";p.write_text(json.dumps(out,indent=2)+chr(10))
print(json.dumps({"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"native_count":len(rows),"source_step_counts":[{"name":k[0],"conclusion":k[1],"count":v} for k,v in sorted(counts.items())],"unexpected_steps":[{"job":r["job_id"],"step":x} for r in rows for x in r["source_steps"] if x["conclusion"]!="success"]}))
