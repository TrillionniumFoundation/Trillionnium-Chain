import json,hashlib,sys
from pathlib import Path
B=Path("/private/tmp/chain-R1-archive-tag-workflow-trigger-review-20261114-v1")
raw=(B/"workflow-trigger-inventory.json").read_bytes()
assert len(raw)==80701 and hashlib.sha256(raw).hexdigest()=="2e2c45e27461018048305cd5ef2d98c88fedda1866acd28c13a432b423844448"
v=json.loads(raw)
rows=[]
for r in v["files"]:
    p=r["parsed_events"];assert isinstance(p,dict)
    rows.append({"path":r["path"],"git_blob":r["git_blob"],"sha256":r["sha256"],"events":list(p),"push":p.get("push"),"create":p.get("create"),"release":p.get("release"),"workflow_run":p.get("workflow_run"),"workflow_call":p.get("workflow_call"),"action_keyword_locations":r["action_keyword_locations"]})
o={"schema":"trnm-r1-archive-tag-trigger-compact-inventory-v1","head":v["head"],"tree":v["tree"],"tag":v["tag"],"yaml_parser_available":v["yaml_parser_available"],"files":rows}
data=(json.dumps(o,sort_keys=True,indent=2)+"\n").encode()
with(B/"compact-trigger-inventory.json").open("xb")as f:f.write(data)
with(B/"compact-trigger-inventory.py").open("xb")as f:f.write(sys.argv[1].encode())
print(json.dumps({"pin":{"path":str(B/"compact-trigger-inventory.json"),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},"data":o},sort_keys=True))
