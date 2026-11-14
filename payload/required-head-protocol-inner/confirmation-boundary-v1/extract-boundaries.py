import os,stat,hashlib,json,struct,zlib,sys,datetime
from pathlib import Path
B=Path("/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1")
SRC=B/"selected-members-v1/ranges/confirmation-report/body"
OUT=B/"confirmation-boundary-v1"
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def sha(b):return hashlib.sha256(b).hexdigest()
s=SRC.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and SRC.resolve(strict=True)==SRC
with os.fdopen(os.open(SRC,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),"rb") as f:
    assert fp(os.fstat(f.fileno()))==fp(s);b=f.read(525936);assert fp(os.fstat(f.fileno()))==fp(s)
assert fp(SRC.lstat())==fp(s) and len(b)==525935 and sha(b)=="9055907e6728bcc52b85498c3349d7932e48ad449f21cd5142b5d334530fcf49"
v=struct.unpack_from("<4s5H3I2H",b,0);n,x=v[-2:];off=30+n+x
raw=zlib.decompress(b[off:off+525848],-15)
assert len(raw)==11707964 and sha(raw)=="71661f80ce81979eefd2ca2353476b534258fe2de112e830c1b8ffb426a9cb83"
r=json.loads(raw)
OUT.mkdir();os.umask(0o077)
def put(n,v):
    raw=(json.dumps(v,indent=2,sort_keys=True)+"\n").encode();p=OUT/n
    with p.open("xb") as f:f.write(raw)
    return {"path":str(p),"bytes":len(raw),"sha256":sha(raw)}
details=[]
for i,p in enumerate(r["phases"]):
    details.append({"json_pointer":f"/phases/{i}","all_keys":list(p),"history":p.get("honest_history"),"submissions":p.get("honest_submissions"),"independent_client_confirmation":p.get("independent_client_confirmation"),"independent_final_confirmation_stage":p.get("independent_final_confirmation_stage"),"confirmation_ended_ns":p.get("confirmation_ended_ns"),"client_confirmed_transactions":p.get("client_confirmed_transactions"),"verification_errors":p.get("verification_errors")})
result={"schema":"trnm-required-protocol-original-business-boundaries-v1","original_range":{"path":str(SRC),"bytes":len(b),"sha256":sha(b)},"report":{"path":"from-zero-native/confirmation/report.json","bytes":len(raw),"sha256":sha(raw)},"phases":details,"no_new_GET":True,"source_stage_Git_tests_unchanged":True}
pin=put("business-boundaries.json",result)
with (OUT/"extract-boundaries.py").open("xb") as f:f.write(sys.argv[1].encode())
assert fp(SRC.lstat())==fp(s)
print(json.dumps({"pin":pin,"pressure":details[1]},sort_keys=True))
