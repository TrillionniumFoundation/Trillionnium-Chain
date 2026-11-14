import json,sys,hashlib,re,os,stat,importlib.util
from pathlib import Path
B=Path("/private/tmp/chain-R1-archive-tag-workflow-trigger-review-20261114-v1")
idxraw=(B/"source-index.json").read_bytes()
assert hashlib.sha256(idxraw).hexdigest()=="b98e6b0130bec20c6e471d22f27e4907bbdd590632ec0f2aa67d2cb9f2fb5da6"
idx=json.loads(idxraw);rows=[]
yaml_spec=importlib.util.find_spec("yaml")
yaml_mod=None
if yaml_spec is not None:
    import yaml as yaml_mod
for item in idx["files"]:
    p=Path(item["source"]["path"]);raw=p.read_bytes()
    assert len(raw)==item["source"]["bytes"] and hashlib.sha256(raw).hexdigest()==item["source"]["sha256"]
    lines=raw.decode().splitlines();start=[i for i,l in enumerate(lines) if re.match(r"^(?:on|\"on\"|'on')\s*:",l)]
    assert len(start)==1
    a=start[0];b=next((i for i in range(a+1,len(lines)) if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:",lines[i])),len(lines))
    parsed=None
    if yaml_mod is not None:
        allvalue=yaml_mod.load(raw.decode(),Loader=yaml_mod.BaseLoader);parsed=allvalue.get("on")
    row={"path":item["path"],"git_blob":item["oid"],"bytes":len(raw),"sha256":item["source"]["sha256"],"event_block_lines":[a+1,b],"on_block":"\n".join(lines[a:b]),"parsed_events":parsed,"event_keyword_locations":[{"line":i+1,"text":l} for i,l in enumerate(lines) if re.search(r"^\s*(create|release|workflow_run|workflow_call|push|tags|tags-ignore|branches|branches-ignore)\s*:",l)],"action_keyword_locations":[{"line":i+1,"text":l} for i,l in enumerate(lines) if re.search(r"(deploy|promot|gh release|release/create|create-release|publish|contents:\s*write|id-token:\s*write|packages:\s*write|environment:)",l,re.I)]}
    rows.append(row)
out={"schema":"trnm-r1-workflow-trigger-inventory-v1","head":idx["head"],"tree":idx["tree"],"tag":idx["tag_candidate"],"yaml_parser_available":yaml_spec is not None,"yaml_loader":"BaseLoader" if yaml_spec else None,"workflow_count":len(rows),"files":rows}
data=(json.dumps(out,indent=2,sort_keys=True)+"\n").encode()
with(B/"workflow-trigger-inventory.json").open("xb")as f:f.write(data)
with(B/"extract-workflow-triggers-v2.py").open("xb")as f:f.write(sys.argv[1].encode())
print(json.dumps({"pin":{"path":str(B/"workflow-trigger-inventory.json"),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},"yaml_available":yaml_spec is not None,"rows":[{"path":r["path"],"blob":r["git_blob"],"lines":r["event_block_lines"],"on":r["on_block"],"actions":r["action_keyword_locations"]}for r in rows]},sort_keys=True))
