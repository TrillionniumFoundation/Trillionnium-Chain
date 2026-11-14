import pathlib,os,sys,json,hashlib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2]
O=pathlib.Path("/private/tmp/chain-prci-remote-5a4b-required-jobs-observation-20261114-v3/terminal-closure-v1");O.mkdir(mode=0o700)
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def save(n,b):
 p=O/n
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
files=[save("producer.py",SELF.encode())]
for op in D["operations"]:
 at=0;raw=b""
 for p in op["reads"]:
  assert p["offset"]==at and not p["truncated_before_offset"] and not p["text_is_lossy"]
  b=bytes.fromhex(p["bytes_hex"]);assert len(b)==p["next_offset"]-p["offset"] and hashlib.sha256(b).hexdigest()==p["chunk_sha256"] and b.decode()==p["text"]
  raw+=b;at=p["next_offset"]
 assert at==p["available_end"] and p["output_complete"]is True and p["status"]["exit_code"]==0
 files.append(save(op["name"]+"-terminal.json",js(op)));files.append(save(op["name"]+"-terminal.log",raw))
for item in (D["summary"],D["status"]):
 b=pathlib.Path(item["path"]).read_bytes();assert len(b)==item["bytes"] and hashlib.sha256(b).hexdigest()==item["sha256"]
summary={"schema":"trnm-fresh-N-observer-v3-terminal-closure-v1","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"operations":2,"all_output_bytes_and_terminal_exit_verified":True,"original_observer_summary":D["summary"],"derived_existing_response_status":D["status"],"no_new_remote_requests_or_stage_source_git_actions":True,"files":files}
sp=save("summary.json",js(summary));files.append(sp)
ip=save("EVIDENCE_INDEX.json",js({"files":files,"self_excluded":True}))
print(json.dumps({"summary":sp,"index":ip,"closed":True}),flush=True)
