import hashlib,json,pathlib,sys
assert sys.flags.optimize==0
out=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/M8-root-execution-originals-v1")
out.mkdir(mode=0o700,exist_ok=False)
items=[]
def emit(name,raw):
 assert pathlib.PurePosixPath(name).name==name
 with (out/name).open("xb") as f:f.write(raw)
 assert (out/name).read_bytes()==raw
 items.append({"path":str(out/name),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
emit("producer.py",sys.argv[1].encode())
for name,text in json.loads(sys.argv[2]):
 emit(name,text.encode())
 if name.endswith("-terminal.json"):
  value=json.loads(text);raw=bytes.fromhex(value["bytes_hex"])
  assert value["offset"]==0 and value["next_offset"]==len(raw) and value["output_complete"] is True
  assert value["status"]["state"]=="exited" and value["truncated_before_offset"] is False
  assert hashlib.sha256(raw).hexdigest()==value["chunk_sha256"]
  emit(name[:-5]+".log",raw)
emit("README.txt",b"Original launch and terminal tool receipts for completed M7/M8 local work. M7 seven-gate failure and the first prewrite inventory guard failure remain failures. The ROG full-lane record is launch-only, not a completed or passing execution. Official binary copy binds complete source size/SHA/version, each actual read and the create-only destination write. No source, Git, network or test action is performed by this materializer.\n")
emit("EVIDENCE_INDEX.json",(json.dumps({"schema":"trnm-root-M8-execution-originals-v1","files":items},indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"directory":str(out),"files":len(items),"bytes":sum(x["bytes"] for x in items)}),flush=True)
