import hashlib,json,os,pathlib,sys
if sys.flags.optimize:raise RuntimeError("optimized recording forbidden")
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");E=R/"R1-payload-content-scan-tool-records-v1";E.mkdir(mode=0o700,exist_ok=False)
values=json.loads(sys.argv[2]);rows=[]
def save(name,data):
 p=E/name
 with p.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
 rows.append({"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
save("producer.py",sys.argv[1].encode())
for name,value in sorted(values.items()):save(name+".json",(json.dumps(value,indent=2,sort_keys=True)+"\n").encode())
save("index.json",(json.dumps({"schema":"trnm-R1-content-scan-actual-tool-records-v1","files":rows.copy()},indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"files":len(rows),"bytes":sum(x["bytes"]for x in rows),"index":rows[-1],"A_terminal":next(x for x in rows if x["path"].endswith("/scan-A-terminal.json"))}),flush=True)
