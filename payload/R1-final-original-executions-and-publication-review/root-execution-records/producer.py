import hashlib,json,os,pathlib,re,sys
assert not sys.flags.optimize
E=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-final-execution-tool-records-v1");E.mkdir(mode=0o700)
d=json.loads(sys.argv[2]);assert d["schema"]=="trnm-root-R1-final-execution-tool-records-v1" and d["head"]=="2a86462a1ab20c68151719ba4635e3c294391e64"
rows=[]
def put(name,b):
 assert re.fullmatch(r"[A-Za-z0-9._-]+",name)
 with (E/name).open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert (E/name).read_bytes()==b;rows.append({"path":name,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
put("producer.py",sys.argv[1].encode())
for name,v in d["records"].items():
 assert v is not None
 put(name,v.encode() if name.endswith(".py") else (json.dumps(v,indent=2,sort_keys=True)+"\n").encode())
for name,exit_code in d["terminal_exits"].items():
 v=d["records"][name];assert v["offset"]==0 and v["status"]["state"]=="exited" and v["status"]["exit_code"]==exit_code and v["output_complete"] is True and v["status"]["capture_error"] is None and v["truncated_before_offset"] is False
 b=bytes.fromhex(v["bytes_hex"]);assert len(b)==v["next_offset"]==v["available_end"] and hashlib.sha256(b).hexdigest()==v["chunk_sha256"]
 put(name.removesuffix(".json")+".log",b)
put("README.txt",(d["note"]+"\n").encode())
i={"schema":d["schema"],"head":d["head"],"tree":d["tree"],"files":rows,"three_R1_Linux_executions":"actual_completed_terminals","hosted_qualification":False}
b=(json.dumps(i,indent=2,sort_keys=True)+"\n").encode();(E/"EVIDENCE_INDEX.json").write_bytes(b)
print(json.dumps({"status":"CLOSED_SOURCE_TOOL_RECORDS_SAVED","directory":str(E),"indexed_files":len(rows),"indexed_bytes":sum(x["bytes"]for x in rows),"index_bytes":len(b),"index_sha256":hashlib.sha256(b).hexdigest()}),flush=True)
