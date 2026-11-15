from pathlib import Path
import json,re,hashlib
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107")
OUT=ROOT/"20261107T153420Z-d26e047dedfc-848e533e/state-artifact-read-v1"
inspection=json.loads((OUT/"native-control-core-inspection-v1.json").read_bytes())
results=[]
for base in inspection["results"]:
 d=OUT/str(base["artifact_id"]);raw=json.loads((d/"readback.json").read_bytes())
 lines=(d/"migration.log").read_text().splitlines()
 terms=[{"line":i+1,"text":v} for i,v in enumerate(lines) if v.startswith("test result:")]
 positive=[x for x in terms if re.fullmatch(r"test result: ok\. [1-9][0-9]* passed; 0 failed;.*",x["text"])]
 assert positive and len(positive)==len(terms)
 assert raw["job_conclusion"]=="success" and len(raw["named_tests"])==6
 assert all(t["strict_reader"]["result"]=="PASS" for t in raw["named_tests"])
 assert raw["source_binding"]["before_after_equal"] and raw["source_binding"]["resolver_context_equal"]
 result={"artifact_id":raw["artifact_id"],"job_id":raw["job_id"],"original_job_conclusion":raw["job_conclusion"],"source_binding":raw["source_binding"],"zip_metadata_digest_verified":True,"retained_zip_sha256":raw["download"]["sha256"],"preserved_initial_observer_errors":raw["errors"],"original_named_controls":{"required":6,"read_back":6,"passed":6},"migration_original_grep_gate_passed":True,"migration_terminal_lines":terms,"migration_main_terminal":terms[-1],"migration_nested_process_summaries":terms[:-1],"migration_summary_counts_must_not_be_added":True,"component_controls_readback_passed":True,"scope":"original-state-component-controls-only","production_or_throughput_gate_validated":False}
 p=d/"readback-addendum-v2.json";p.write_text(json.dumps(result,indent=2)+chr(10))
 results.append(result)
out={"schema":"trnm-independent-state-readback-addendum-v2","expected_matrix_lanes":4,"completed_lanes_in_snapshot":2,"results":results,"remaining_x64_lanes_pending_as_of_original_snapshot":2,"native_business_gate_validated":False}
p=OUT/"summary-addendum-v2.json";p.write_text(json.dumps(out,indent=2)+chr(10))
light=ROOT/"light-business-evidence-d26-v1"
files=[{"path":str(x),"bytes":x.stat().st_size,"sha256":hashlib.sha256(x.read_bytes()).hexdigest()} for x in (p,light/"CORE.json",light/"COPY_PLAN.json",ROOT/"original-business-readback-v1.json",ROOT/"original-business-core-v1.json")]
latest=sorted(ROOT.glob("20261107T*-d26e047dedfc-*"))[-1]
print(json.dumps({"files":files,"state_results":results,"latest_snapshot_directory":str(latest),"latest_snapshot_complete":(latest/"snapshot.json").exists()}))
