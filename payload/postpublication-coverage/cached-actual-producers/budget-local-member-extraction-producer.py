import os,stat,json,hashlib,zipfile,io,zlib,sys
from pathlib import Path
BASE=Path("/private/tmp/chain-prci-R1-budget-three-artifact-originals-20261114-v1")
OUT=BASE/"inner-originals-v1"
def need(v,c):
 if not v:raise ValueError(c)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n,h):
 p=Path(p);s=p.lstat();need(p.resolve()==p and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==n,"PIN_TYPE")
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:
  need(fp(os.fstat(f.fileno()))==fp(s),"PIN_OPEN")
  b=f.read(n+1);need(fp(os.fstat(f.fileno()))==fp(s),"PIN_FD_CHANGED")
 need(fp(p.lstat())==fp(s)and len(b)==n and hashlib.sha256(b).hexdigest()==h,"PIN_SHA")
 return b
def save(d,name,b):
 p=d/name
 with p.open("xb")as f:f.write(b)
 need(p.read_bytes()==b,"TARGET_READBACK")
 return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
OUT.mkdir(mode=0o700,exist_ok=False)
results=[]
for spec in json.loads(sys.argv[1]):
 d=OUT/str(spec["artifact"]);d.mkdir(mode=0o700)
 zp=BASE/str(spec["artifact"])/(str(spec["artifact"])+".zip")
 raw=read(zp,spec["bytes"],spec["sha256"])
 ip=spec["index_pin"];index=json.loads(read(ip["path"],ip["bytes"],ip["sha256"]))
 members={r["path"]:r for r in index["members"]}
 allowed={"native/driver-preflight.process.json","native/driver-preflight.stdout","native/driver-preflight.stderr","native/driver-source-before.json","native/driver-source-after.json","native/subject-preflight.process.json","native/subject-preflight.stdout","native/subject-preflight.stderr","native/subject-source-before.json","native/subject-source-after.json","native/report.json","request.txt","runner-controls.stdout","runner-controls.stderr"}
 need(set(members)==allowed and len(members)==14,"EXACT_FOURTEEN_TEXT_FILES")
 copies=[];contents={}
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  for name in sorted(allowed):
   b=z.read(name);r=members[name]
   need(len(b)==r["bytes"] and hashlib.sha256(b).hexdigest()==r["sha256"]and f"{zlib.crc32(b)&0xffffffff:08x}"==r["crc32"],"MEMBER_PIN")
   b.decode("utf-8")
   copies.append({"zip_member":name,"origin_zip":str(zp),"raw":save(d,name.replace("/","--"),b)})
   contents[name]=b
 report=json.loads(contents["native/report.json"])
 driver=json.loads(contents["native/driver-source-before.json"]);subject=json.loads(contents["native/subject-source-before.json"])
 result={"artifact":spec["artifact"],"job":spec["job"],"run":43604217513,"run_attempt":1,"metadata_head":"2a86462a1ab20c68151719ba4635e3c294391e64","expected_historical_subject":spec["subject"],"driver_before_after_byte_equal":contents["native/driver-source-before.json"]==contents["native/driver-source-after.json"],"subject_before_after_byte_equal":contents["native/subject-source-before.json"]==contents["native/subject-source-after.json"],"driver_source":driver,"subject_source":subject,"report":report,"copies":copies,"runner_controls_stderr_last_lines":contents["runner-controls.stderr"].decode().splitlines()[-8:],"native_tests_executed_here":False,"qualification":False}
 rec=save(d,"extraction-summary.json",(json.dumps(result,indent=2,sort_keys=True)+"\n").encode())
 results.append({"summary":rec,"artifact":spec["artifact"],"report":report,"driver_source":driver,"subject_source":subject,"driver_before_after_byte_equal":result["driver_before_after_byte_equal"],"subject_before_after_byte_equal":result["subject_before_after_byte_equal"],"runner_controls_tail":result["runner_controls_stderr_last_lines"]})
print(json.dumps(results,sort_keys=True),flush=True)
