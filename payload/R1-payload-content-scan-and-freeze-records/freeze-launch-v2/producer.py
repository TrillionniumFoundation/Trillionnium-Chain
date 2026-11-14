import hashlib,json,os,pathlib,sys
if sys.flags.optimize:raise RuntimeError("optimized launcher forbidden")
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
assert ROOT.resolve(strict=True)==ROOT
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError("duplicate key")
  d[k]=v
 return d
def nonfinite(v):raise ValueError("nonfinite input")
inputs=json.loads(sys.argv[2],object_pairs_hook=unique,parse_constant=nonfinite)
assert type(inputs)is dict and set(inputs)=={"phase","groups"}
phase=inputs["phase"];assert phase=="content"
groups=inputs["groups"];assert type(groups)is list and groups
driver=ROOT/"execution-manifest-freezer-preparation-v1/freeze_execution_payload_v2.py"
raw=driver.read_bytes()
assert len(raw)==15047 and hashlib.sha256(raw).hexdigest()=="38642c29417a4f37e9f1ca6693c71d0d1bc08a9904950470049efdfc66700139"
E=ROOT/("R1-payload-freeze-launch-"+phase+"-v2");E.mkdir(mode=0o700,exist_ok=False)
def save(path,data):
 with path.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
 assert path.read_bytes()==data
 return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
save(E/"producer.py",sys.argv[1].encode());save(E/"inputs.json",(json.dumps(inputs,indent=2,sort_keys=True)+"\n").encode())
desc=(json.dumps(groups,indent=2,sort_keys=True)+"\n").encode()
pin=save(ROOT/("frozen-execution-payload-descriptor-2a8646-"+phase+"-v2.json"),desc)
out=ROOT/("frozen-execution-payload-2a8646-"+phase+"-v2")
print(json.dumps({"phase":phase,"descriptor":pin,"groups":len(groups),"files":sum(x["count"]for x in groups),"bytes":sum(x["bytes"]for x in groups),"output_dir":str(out)}),flush=True)
sys.argv=[str(driver),"--descriptor",pin["path"],"--descriptor-sha256",pin["sha256"],"--output-dir",str(out)]
exec(compile(raw,str(driver),"exec",optimize=0),{"__name__":"__main__","__file__":str(driver)})
