import hashlib,json,os,pathlib,re,sys,types
if sys.flags.optimize:raise RuntimeError("optimized scope execution forbidden")
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
PREP=pathlib.Path("/private/tmp/chain-execution-payload-credential-scanner-20261114-v1")
driver=PREP/"scan_frozen_execution_payload_v2.py";raw=driver.read_bytes()
assert len(raw)==14664 and hashlib.sha256(raw).hexdigest()=="14305dfe4b3edaecb601dffed336a13c916fe6a9182a9547770f0637031b50b6"
mod=types.ModuleType("reviewed_payload_manifest_validation");exec(compile(raw,str(driver),"exec"),mod.__dict__)
def unique_pairs(pairs):
 out={}
 for key,value in pairs:
  if key in out:raise ValueError("duplicate input key")
  out[key]=value
 return out
def forbidden_constant(value):raise ValueError("nonfinite input number")
inputs=json.loads(sys.argv[2],object_pairs_hook=unique_pairs,parse_constant=forbidden_constant)
assert type(inputs)is dict and set(inputs)=={"baseline_manifest","full_manifest","phase"}
phase=inputs["phase"];assert type(phase)is str and phase in ("content","scan-records")
program_path=pathlib.Path(__file__)
assert program_path==ROOT/"R1-payload-scope-static-review-input-v2/prepare_scope_and_scan.py"
program_raw,program_identity=mod.absolute_snapshot(program_path,16384)
assert program_raw==sys.argv[1].encode()
E=ROOT/("R1-execution-payload-scope-"+phase+"-v1");E.mkdir(mode=0o700,exist_ok=False)
def save(name,data):
 path=E/name
 with path.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
 return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
save("producer.py",program_raw);save("inputs.json",(json.dumps(inputs,indent=2,sort_keys=True)+"\n").encode())
def read_manifest(pin):
 assert type(pin)is dict and set(pin)=={"path","bytes","sha256"}
 assert type(pin["bytes"])is int and 0<pin["bytes"]<=16*1024*1024
 assert type(pin["sha256"])is str and re.fullmatch(r"[0-9a-f]{64}",pin["sha256"])
 path=mod.absolute_path(pin["path"]);assert path.is_relative_to(ROOT)
 raw,identity=mod.absolute_snapshot(path,16*1024*1024)
 assert len(raw)==pin["bytes"] and hashlib.sha256(raw).hexdigest()==pin["sha256"]
 data,payload,rows=mod.validate_manifest(raw)
 assert payload==ROOT/"execution-receipts-followup-v1"
 return data,rows,identity
P=str(ROOT/"frozen-execution-payload-2a8646-content-v1/frozen-execution-payload-manifest-v1.json")
F=str(ROOT/"frozen-execution-payload-2a8646-publication-v1/frozen-execution-payload-manifest-v1.json")
baseline,old,old_id=read_manifest(inputs["baseline_manifest"]);full,rows,full_id=read_manifest(inputs["full_manifest"])
if phase=="content":assert inputs["full_manifest"]["path"]==P
else:assert inputs["baseline_manifest"]["path"]==P and inputs["full_manifest"]["path"]==F
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
assert mod.absolute_snapshot(program_path,16384)[1]==program_identity
print(json.dumps({"scope_prepared":True,"phase":phase,"scope_manifest":pin,"new_files":len(new),"new_bytes":scope["total_bytes"],"full_files":len(rows),"full_bytes":full["total_bytes"]}),flush=True)
os.execv("/opt/homebrew/bin/python3",["/opt/homebrew/bin/python3","-B",str(driver),"--manifest",pin["path"],"--manifest-sha256",pin["sha256"],"--evidence-dir",str(PREP/("run-R1-"+phase+"-v1"))])
