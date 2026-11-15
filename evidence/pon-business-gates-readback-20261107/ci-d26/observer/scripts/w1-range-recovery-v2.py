from pathlib import Path
import subprocess,json,hashlib,os
R=Path("/home/qian-qi/throughput-ci-observation-20261107/20261107T151751Z-d26e047dedfc-35b656b0")
ID="13579071557";O=R/"w1-range-recovery-v2"/ID;O.mkdir(parents=True)
candidates=[]
for name in ("w1-component-artifact-read-v1","w1-component-artifact-retry-v2"):
 d=R/name/ID
 if (d/"readback.json").exists():
  old=json.loads((d/"readback.json").read_bytes())
  if old["errors"]:candidates.append((d/"artifact.zip",old))
assert candidates
p,old=max(candidates,key=lambda x:x[0].stat().st_size);a=old["metadata"];total=a["size_in_bytes"];start=p.stat().st_size
assert 0<start<total and a["id"]==int(ID)
row={"artifact_id":int(ID),"metadata":a,"prefix_path":str(p),"prefix_bytes":start,"prefix_original_errors":old["errors"],"requests":[],"errors":[],"completed":False,"native_gate_validated":False}
part=O/"artifact.zip.partial";h=hashlib.sha256()
with p.open("rb") as inp,part.open("xb") as out:
 while b:=inp.read(1024*1024):h.update(b);out.write(b)
assert p.stat().st_size==start and part.stat().st_size==start
row["prefix_sha256"]=h.hexdigest()
print(json.dumps({"phase":"prefix-preserved","artifact":int(ID),"prefix_bytes":start,"remaining_bytes":total-start}),flush=True)
try:
 number=0
 while start<total:
  end=min(total-1,start+8*1024*1024-1);number+=1
  argv=["/usr/bin/gh","api","--hostname","github.com","--method","GET","--include","--header",f"Range: bytes={start}-{end}","repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+ID+"/zip"]
  response=O/f"range-{number:02d}.http";stderr=O/f"range-{number:02d}.stderr";req={"argv":argv,"start":start,"end":end}
  row["requests"].append(req)
  with response.open("xb") as out,stderr.open("xb") as err:
   process=subprocess.run(argv,stdout=out,stderr=err,timeout=180)
  req["exit_code"]=process.returncode
  assert response.stat().st_size<9*1024*1024
  raw=response.read_bytes();head,sep,body=raw.partition(b"\r\n\r\n")
  if not sep:head,sep,body=raw.partition(b"\n\n")
  assert sep and head.startswith(b"HTTP/");status=int(head.splitlines()[0].split()[1]);headers={}
  for line in head.splitlines()[1:]:
   k,colon,v=line.partition(b":")
   if colon:headers[k.decode().lower()]=v.decode().strip()
  req.update(status=status,body_bytes=len(body),body_sha256=hashlib.sha256(body).hexdigest(),headers={k:v for k,v in headers.items() if k in ("content-range","content-length","content-type","etag")})
  assert process.returncode==0 and status==206 and headers.get("content-range")==f"bytes {start}-{end}/{total}" and len(body)==end-start+1
  with part.open("ab") as out:out.write(body)
  h.update(body);start=end+1
  print(json.dumps({"phase":"range-retained","artifact":int(ID),"request":number,"received":len(body),"remaining_bytes":total-start}),flush=True)
 assert part.stat().st_size==total and "sha256:"+h.hexdigest()==a["digest"]
 part.rename(O/"artifact.zip");row.update(completed=True,zip_bytes=total,zip_sha256=h.hexdigest())
except Exception as e:row["errors"].append(type(e).__name__+": "+str(e))
(O/"range-recovery-receipt.json").write_text(json.dumps(row,indent=2)+chr(10))
print(json.dumps({"directory":str(O),"artifact":int(ID),"completed":row["completed"],"zip_bytes":row.get("zip_bytes"),"zip_sha256":row.get("zip_sha256"),"request_count":len(row["requests"]),"errors":row["errors"]}),flush=True)
