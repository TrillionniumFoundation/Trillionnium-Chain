import hashlib,json,os,pathlib,re,stat
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1")
O=E/"fixture-and-original-results-v1";O.mkdir(exist_ok=False)
def rd(path,cap):
 path=pathlib.Path(path)
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap
  b=f.read(cap+1);z=os.fstat(f.fileno());assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and len(b)==a.st_size
 return b
fixture=E/"source-capture-v1/trillionnium--crates--trnm-pon-node--tests--public_v3_from_zero.rs.raw"
raw=rd(fixture,100000);assert hashlib.sha256(raw).hexdigest()=="c20a1d34bcb4ad9d0f37a9b65815aac3c9e50b267edb9a65e856b3acd954064f"
lines=raw.decode().splitlines()
for name,ranges in [("fixture-environment.txt",[(1,108),(270,355),(486,569)]),("fixture-confirmation-loop.txt",[(1235,1480)]),("fixture-confirmation-result.txt",[(1481,1676)]),("fixture-confirmation-test.txt",[(1677,len(lines))])]:
 out="\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,min(b,len(lines)))) for a,b in ranges)+"\n"
 (O/name).write_text(out)
B=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1/inner-originals-v1")
results=[]
for artifact in ["14111407094","14111816359"]:
 m=B/artifact/"from-zero-native/manifest.json";mr=rd(m,32*1024*1024);doc=json.loads(mr)
 rp=B/artifact/"from-zero-native/confirmation/report.json";rr=rd(rp,32*1024*1024);r=json.loads(rr)
 phases=[]
 for ph in r["phases"]:
  scalar={k:v for k,v in ph.items() if v is None or isinstance(v,(bool,int,float,str))}
  arrays={k:len(v) for k,v in ph.items() if isinstance(v,list)}
  replay=ph.get("independent_replay_stages",ph.get("independent_replays",None))
  dictionaries={k:sorted(v.keys()) for k,v in ph.items() if isinstance(v,dict)}
  phases.append({"scalars":scalar,"array_counts":arrays,"dictionary_keys":dictionaries,"replays":replay})
 results.append({"artifact_id":artifact,"manifest":{"path":str(m),"bytes":len(mr),"sha256":hashlib.sha256(mr).hexdigest(),"keys":sorted(doc),"passed":doc.get("passed"),"failures":doc.get("failures"),"runs":[{"name":x.get("name"),"passed":x.get("passed"),"process":{k:x.get("process",{}).get(k) for k in ("exit_code","timed_out","elapsed_seconds","wall_ns")}} for x in doc.get("runs",[])],"terminal":doc.get("terminal")},"report":{"path":str(rp),"bytes":len(rr),"sha256":hashlib.sha256(rr).hexdigest(),"keys":sorted(r),"top_scalars":{k:v for k,v in r.items() if v is None or isinstance(v,(bool,int,float,str))},"phases":phases}})
(O/"original-N-result-extract.json").write_text(json.dumps(results,indent=2,sort_keys=True)+"\n")
print(json.dumps({"dir":str(O),"files":[{"name":p.name,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(O.iterdir())],"N_summaries":[{"artifact":x["artifact_id"],"passed":x["manifest"]["passed"],"failures":x["manifest"]["failures"],"phase_keys":[{"mode":p["scalars"].get("mode"),"array_counts":p["array_counts"],"dictionary_keys":p["dictionary_keys"]} for p in x["report"]["phases"]]} for x in results]},sort_keys=True))
