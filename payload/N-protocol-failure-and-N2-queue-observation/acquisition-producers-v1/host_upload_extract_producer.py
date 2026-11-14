import json,pathlib,re
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
out=[]
for i in [132415017391,132415017476]:
 p=R/"initial-GET-v1"/("job"+str(i)+"-original-log.stdout")
 lines=p.read_text().splitlines();events=[];artifacts=[]
 for n,line in enumerate(lines,1):
  if any(x in line for x in ["Artifact name","Artifact Name","Artifact ID","Artifact download URL","SHA256 digest","name: trnm"]):artifacts.append({"line":n,"text":line})
  pos=line.find("{")
  if pos>=0:
   try:v=json.loads(line[pos:])
   except (ValueError,TypeError):continue
   if isinstance(v,dict) and v.get("schema")=="trnm-ci-original-public-host-controller-v2":
    events.append({"line":n,"schema":v["schema"],"command_argv":v.get("command_argv"),"passed":v.get("passed"),"systemd_run_exit":v.get("systemd_run_exit"),"failure":v.get("failure"),"final_host_errors":v.get("final_host_errors"),"preparation_completed":v.get("preparation",{}).get("completed"),"preparation_failure_type":v.get("preparation",{}).get("failure_type"),"source_before":v.get("preparation",{}).get("source_before"),"source_after":v.get("preparation",{}).get("source_after")})
 out.append({"job_id":i,"host_events":events,"artifact_upload_lines":artifacts})
dest=R/"initial-cause-extract-v1"/"bounded-host-and-upload-facts.json"
with dest.open("xb") as f:f.write((json.dumps(out,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(out,sort_keys=True))
