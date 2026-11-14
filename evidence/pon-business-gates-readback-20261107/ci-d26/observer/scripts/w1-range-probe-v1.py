from pathlib import Path
import subprocess,json,hashlib,re
R=Path("/home/qian-qi/throughput-ci-observation-20261107")
S=R/"20261107T151751Z-d26e047dedfc-35b656b0/w1-component-artifact-read-v1/13578947026"
O=R/"20261107T151751Z-d26e047dedfc-35b656b0/w1-range-readonly-probe-v1";O.mkdir()
old=json.loads((S/"readback.json").read_bytes());a=old["metadata"];prefix=(S/"artifact.zip").read_bytes();start=len(prefix)
assert start==5455872 and a["size_in_bytes"]==5571168
argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET","--include","--header",f"Range: bytes={start}-","repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/13578947026/zip"]
result={"artifact_id":a["id"],"metadata":a,"argv":argv,"old_attempt":str(S/"readback.json"),"old_prefix_bytes":start,"old_prefix_sha256":hashlib.sha256(prefix).hexdigest(),"errors":[],"native_gate_validated":False}
try:
 with (O/"range-response.http").open("xb") as out,(O/"download.stderr").open("xb") as err:p=subprocess.run(argv,stdout=out,stderr=err,timeout=120)
 result["exit_code"]=p.returncode
 raw=(O/"range-response.http").read_bytes();assert len(raw)<8*1024*1024
 head,sep,body=raw.partition(b"\r\n\r\n")
 if not sep:head,sep,body=raw.partition(b"\n\n")
 assert sep and head.startswith(b"HTTP/")
 status=int(head.splitlines()[0].split()[1]);headers={}
 for line in head.splitlines()[1:]:
  key,colon,value=line.partition(b":")
  if colon:headers[key.decode().lower()]=value.decode().strip()
 result["response"]={"status":status,"body_bytes":len(body),"body_sha256":hashlib.sha256(body).hexdigest(),"headers":{k:v for k,v in headers.items() if k in ("content-range","content-length","content-type","etag")}}
 assert p.returncode==0
 if status==206:
  assert headers.get("content-range")==f"bytes {start}-{a['size_in_bytes']-1}/{a['size_in_bytes']}"
  result["range_honored"]=True;combined=prefix+body
 elif status==200:
  result["range_honored"]=False;combined=body
 else:raise ValueError("unexpected HTTP status")
 assert len(combined)==a["size_in_bytes"] and "sha256:"+hashlib.sha256(combined).hexdigest()==a["digest"]
 (O/"artifact.zip").write_bytes(combined)
 result["recovered_full_zip_sha256"]=hashlib.sha256(combined).hexdigest()
except Exception as e:result["errors"].append(type(e).__name__+": "+str(e))
(O/"receipt.json").write_text(json.dumps(result,indent=2)+chr(10))
print(json.dumps({k:v for k,v in result.items() if k!="metadata"}))
