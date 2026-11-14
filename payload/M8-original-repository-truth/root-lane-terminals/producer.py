import hashlib,json,os,pathlib,re,sys
assert not sys.flags.optimize
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
ev=root/"M8-root-lane-terminals-v1";ev.mkdir(mode=0o700)
data=json.loads(sys.argv[2]);assert data["schema"]=="trnm-root-M8-closed-lane-tool-records-v1"
assert data["head"]=="ed0d35487f2a67239e4d646fd41c2c7acb5cc740"
rows=[]
def write(name,raw):
 assert re.fullmatch(r"[A-Za-z0-9._-]+",name) and "/" not in name
 with (ev/name).open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert (ev/name).read_bytes()==raw
 rows.append({"path":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
write("producer.py",sys.argv[1].encode())
for name,value in data["records"].items():
 assert value is not None,name
 raw=value.encode() if name.endswith(".py") else (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
 write(name,raw)
for name in data["terminal_keys"]:
 value=data["records"][name]
 assert value["offset"]==0 and value["status"]["state"]=="exited" and value["status"]["exit_code"]==0 and value["output_complete"] is True and value["status"]["capture_error"] is None
 assert value["truncated_before_offset"] is False
 raw=bytes.fromhex(value["bytes_hex"])
 assert len(raw)==value["next_offset"]==value["available_end"] and hashlib.sha256(raw).hexdigest()==value["chunk_sha256"]
 write(name.removesuffix(".json")+".log",raw)
write("README.txt",(data["note"]+"\n").encode())
index={"schema":data["schema"],"head":data["head"],"tree":data["tree"],"files":rows,"external_result":"launch_only_not_observed","hosted_qualification":False}
raw=(json.dumps(index,indent=2,sort_keys=True)+"\n").encode()
with (ev/"EVIDENCE_INDEX.json").open("xb") as f:f.write(raw)
print(json.dumps({"status":"CLOSED_TOOL_RECORDS_SAVED","directory":str(ev),"indexed_files":len(rows),"indexed_bytes":sum(x["bytes"] for x in rows),"index_sha256":hashlib.sha256(raw).hexdigest()}),flush=True)
