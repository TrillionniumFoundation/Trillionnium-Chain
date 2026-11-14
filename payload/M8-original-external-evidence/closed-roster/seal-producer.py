import pathlib,os,sys,json,hashlib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2]
O=pathlib.Path("/private/tmp/chain-prci-M8-closed-external-roster-observation-20261114-v1");O.mkdir(mode=0o700)
C=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/original-external-evidence-ed0d35-copy-v1-prci");C.mkdir(mode=0o700)
F=pathlib.Path("/private/tmp/chain-prci-M8-original-repository-truth-materialization-20261114-v1/terminal-closure-v1");F.mkdir(mode=0o700)
def js(x):return (json.dumps(x,indent=2)+"\n").encode()
def save(p,b):
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
rows=[]
rows.append(save(O/"roster-observer.py",D["roster_producer"].encode()))
rows.append(save(O/"roster-observer-launch.json",js(D["roster_launch"])))
rows.append(save(O/"closed-roster-observation.json",js(D["report"])))
manifest=save(O/"closed-original-logs.json",js(D["report"]["closed_manifest"]));rows.append(manifest)
assert manifest["bytes"]==D["report"]["closed_manifest_identity"]["bytes"] and manifest["sha256"]==D["report"]["closed_manifest_identity"]["sha256"]
for key,base in [("roster_terminal","roster-observer"),("original_terminal","original-external")]:
 t=D[key];assert t["status"]["exit_code"]==0 and t["output_complete"]is True and t["offset"]==0 and t["next_offset"]==t["available_end"]
 raw=bytes.fromhex(t["bytes_hex"]);assert len(raw)==t["next_offset"] and hashlib.sha256(raw).hexdigest()==t["chunk_sha256"]
 rows.append(save(O/(base+"-terminal.json"),js(t)));rows.append(save(O/(base+"-terminal.log"),raw))
rows.append(save(O/"seal-producer.py",SELF.encode()))
rows.append(save(O/"README.md",("# M8 closed external-evidence receipt roster\n\nThe actual external lane finished successfully on ed0d35487f2a67239e4d646fd41c2c7acb5cc740 / tree 1aa9c21812489080980bdc3c1c2bb43611e88354. This record contains an independent read-only observation of all 27 original flat files and the actual complete tool terminal. No nested files existed. The manifest deliberately has an empty log list and the packager must reject any unlisted file. No source, Git, test or stage action was performed by this observation. This is not hosted qualification and does not rewrite earlier launch-only observations.\n").encode()))
idx=save(O/"EVIDENCE_INDEX.json",js({"schema":"trnm-M8-closed-external-roster-index-v1","files":rows}))
summary=save(O/"summary.json",js({"schema":"trnm-M8-closed-external-roster-completion-v1","status":"readonly_manifest_prepared","original_status":"passed","original_count":27,"original_bytes":112500,"nested_count":0,"manifest":manifest,"index":idx,"original_summary":D["report"]["original_summary"],"source_identity":D["report"]["source_identity"],"stage_changed":False,"hosted_qualification":False,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}))
t=D["full_materialization_terminal"];assert t["status"]["exit_code"]==0 and t["output_complete"]is True and t["offset"]==0 and t["next_offset"]==t["available_end"]
raw=bytes.fromhex(t["bytes_hex"]);assert hashlib.sha256(raw).hexdigest()==t["chunk_sha256"] and len(raw)==t["next_offset"]
fr=[save(F/"continuation-launch.json",js(D["full_materialization_launch"])),save(F/"continuation-terminal.json",js(t)),save(F/"continuation-terminal.log",raw),save(F/"seal-producer.py",SELF.encode())]
fi=save(F/"EVIDENCE_INDEX.json",js({"schema":"trnm-M8-full-materialization-actual-terminal-closure-v1","files":fr,"prior_failed_v1_preserved_in":"../continuation-v2/previous-materializer-terminal.json","stage_changed":False}))
print(json.dumps({"roster_summary":summary,"roster_manifest":manifest,"roster_index":idx,"full_materializer_terminal_index":fi,"copy_destination":str(C),"stage_changed":False}),flush=True)
