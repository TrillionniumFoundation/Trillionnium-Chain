import hashlib,json,pathlib,re
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=R/"initial-cause-extract-v1";D.mkdir(mode=0o700)
I=R/"initial-GET-v1"
pr=json.loads((I/"pr847.stdout").read_bytes());run=json.loads((I/"N-run43582713392.stdout").read_bytes())
required=json.loads((I/"main-required-status-checks.stdout").read_bytes())
summary={"pr":{"head":pr["head"]["sha"],"base":pr["base"]["sha"],"draft":pr["draft"],"state":pr["state"],"mergeable_state":pr["mergeable_state"],"merge_commit_sha":pr["merge_commit_sha"],"updated_at":pr["updated_at"]},"N_run":{k:run.get(k) for k in ["id","head_sha","head_branch","path","event","status","conclusion","run_attempt","created_at","updated_at","html_url"]},"required":required,"jobs":[]}
for ident in [132415017391,132415017476]:
 name="job"+str(ident)
 job=json.loads((I/(name+".stdout")).read_bytes())
 raw=(I/(name+"-original-log.stdout")).read_bytes()
 text=raw.decode("utf-8",errors="strict");lines=text.splitlines()
 pattern=re.compile(r"Traceback|AssertionError|CONFIRMATION_TARGET|ERROR:|error:|FAILED|Process completed|Error:|native.*failed|timeout|timed out|run_from_zero_native.py|ci_job.sh protocol-contract|Execute the same lane",re.I)
 hit=[i for i,line in enumerate(lines) if pattern.search(line)]
 selected=set(range(max(0,len(lines)-115),len(lines)))
 for i in hit:
  selected.update(range(max(0,i-4),min(len(lines),i+9)))
 out="\n".join(f"{i+1}: {lines[i]}" for i in sorted(selected))+"\n"
 with (D/(name+"-failure-context.txt")).open("xb") as f:f.write(out.encode())
 matches=[{"line":i+1,"text":lines[i]} for i in hit]
 summary["jobs"].append({"id":ident,"name":job["name"],"run_id":job["run_id"],"head_sha":job.get("head_sha"),"status":job["status"],"conclusion":job["conclusion"],"started_at":job["started_at"],"completed_at":job["completed_at"],"failed_steps":[s for s in job["steps"] if s.get("conclusion")=="failure"],"original_log_bytes":len(raw),"original_log_sha256":hashlib.sha256(raw).hexdigest(),"total_lines":len(lines),"context_bytes":len(out.encode()),"matches":matches})
names=(R/"immutable-N-R1-source-delta-v1"/"N-to-R1-names.stdout").read_text().splitlines()
summary["N_to_R1_non_evidence_changed_paths"]=[x for x in names if not x.split("\t")[-1].startswith(("evidence/","docs/audit/"))]
with (D/"summary.json").open("xb") as f:f.write((json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps(summary,sort_keys=True))
for ident in [132415017391,132415017476]:
 lines=(D/("job"+str(ident)+"-failure-context.txt")).read_text().splitlines()
 print("\n".join(lines[-65:]))
