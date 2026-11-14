import hashlib,json,os,pathlib,sys,types
assert not sys.flags.optimize
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
PREP=pathlib.Path("/private/tmp/chain-execution-payload-credential-scanner-20261114-v1")
driver=PREP/"scan_frozen_execution_payload_v2.py";raw=driver.read_bytes()
assert len(raw)==14664 and hashlib.sha256(raw).hexdigest()=="14305dfe4b3edaecb601dffed336a13c916fe6a9182a9547770f0637031b50b6"
mod=types.ModuleType("reviewed_payload_manifest_validation");exec(compile(raw,str(driver),"exec"),mod.__dict__)
inputs=json.loads(sys.argv[2]);assert set(inputs)=={"baseline_manifest","full_manifest","phase"}
phase=inputs["phase"];assert phase in ("content","scan-records")
E=ROOT/("R1-execution-payload-scope-"+phase+"-v1");E.mkdir(mode=0o700,exist_ok=False)
def save(name,data):
 path=E/name
 with path.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
 return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
save("producer.py",sys.argv[1].encode());save("inputs.json",(json.dumps(inputs,indent=2,sort_keys=True)+"\n").encode())
def read_manifest(pin):
 assert set(pin)=={"path","bytes","sha256"}
 path=mod.absolute_path(pin["path"]);assert path.is_relative_to(ROOT)
 raw,identity=mod.absolute_snapshot(path,16*1024*1024)
 assert len(raw)==pin["bytes"] and hashlib.sha256(raw).hexdigest()==pin["sha256"]
 data,payload,rows=mod.validate_manifest(raw)
 assert payload==ROOT/"execution-receipts-followup-v1"
 return data,rows,identity
baseline,old,old_id=read_manifest(inputs["baseline_manifest"]);full,rows,full_id=read_manifest(inputs["full_manifest"])
old_map={r["path"]:r for r in old};all_map={r["path"]:r for r in rows}
assert set(old_map)<=set(all_map) and all(all_map[p]==r for p,r in old_map.items())
new=[r for r in rows if r["path"]not in old_map];assert new
assert len(old)+len(new)==len(rows) and sum(r["bytes"]for r in old)+sum(r["bytes"]for r in new)==full["total_bytes"]
if phase=="content":
 assert inputs["baseline_manifest"]=={"path":str(ROOT/"frozen-execution-payload-2a6206-prescan-v1/frozen-execution-payload-manifest-v1.json"),"bytes":855220,"sha256":"6869bb859742174128f390f6d868f73c49559f5b8e354425dff5eccf06f762d4"}
 assert baseline["file_count"]==2100 and baseline["total_bytes"]==150184002
scope={"schema":"trnm-frozen-execution-payload-manifest-v1","payload_root":full["payload_root"],"file_count":len(new),"total_bytes":sum(r["bytes"]for r in new),"files":new}
scope_raw=(json.dumps(scope,indent=2,sort_keys=True)+"\n").encode();mod.validate_manifest(scope_raw)
pin=save("delta-payload-manifest.json",scope_raw)
proof={"schema":"trnm-frozen-payload-disjoint-scope-proof-v1","phase":phase,"baseline_manifest":inputs["baseline_manifest"],"full_manifest":inputs["full_manifest"],"scope_manifest":pin,"baseline_files":len(old),"baseline_bytes":sum(r["bytes"]for r in old),"new_files":len(new),"new_bytes":scope["total_bytes"],"full_files":len(rows),"full_bytes":full["total_bytes"],"baseline_rows_all_exactly_preserved":True,"full_equals_disjoint_union_of_baseline_and_new":True,"origins_preserved":True,"no_payload_file_or_Git_mutation":True,"scope_only_not_whole_payload_scan_claim":True}
save("coverage-union-proof.json",(json.dumps(proof,indent=2,sort_keys=True)+"\n").encode())
assert read_manifest(inputs["baseline_manifest"])[2]==old_id and read_manifest(inputs["full_manifest"])[2]==full_id
print(json.dumps({"scope_prepared":True,"phase":phase,"scope_manifest":pin,"new_files":len(new),"new_bytes":scope["total_bytes"],"full_files":len(rows),"full_bytes":full["total_bytes"]}),flush=True)
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--manifest",pin["path"],"--manifest-sha256",pin["sha256"],"--evidence-dir",str(PREP/("run-R1-"+phase+"-v1"))])
