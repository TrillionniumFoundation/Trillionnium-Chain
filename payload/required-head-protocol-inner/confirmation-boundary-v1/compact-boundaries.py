import os,stat,hashlib,json,sys
from pathlib import Path
B=Path("/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1/confirmation-boundary-v1")
P=B/"business-boundaries.json"
def sha(x):return hashlib.sha256(x).hexdigest()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
s=P.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and P.resolve(strict=True)==P
with os.fdopen(os.open(P,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),"rb") as f:
    assert fp(os.fstat(f.fileno()))==fp(s);raw=f.read(842708);assert fp(os.fstat(f.fileno()))==fp(s)
assert len(raw)==842707 and sha(raw)=="13b5399bfd017a776aaf9b21f0aae7911cfaf18b6aafddbcff097622ffda4660" and fp(P.lstat())==fp(s)
v=json.loads(raw)
def compact(x,path):
    if isinstance(x,str) and len(x)>256:return {"omitted_long_string_chars":len(x),"original_json_pointer":path}
    if isinstance(x,list):return [compact(y,path+"/"+str(i)) for i,y in enumerate(x)]
    if isinstance(x,dict):return {k:compact(y,path+"/"+k.replace("~","~0").replace("/","~1")) for k,y in x.items()}
    return x
o={"schema":"trnm-required-protocol-compact-business-boundaries-v1","source":{"path":str(P),"bytes":len(raw),"sha256":sha(raw)},"report":v["report"],"phases":[compact(p,p["json_pointer"]) for p in v["phases"]],"only_long_packet_strings_omitted":True}
b=(json.dumps(o,sort_keys=True,indent=2)+"\n").encode();assert len(b)<=65536
out=B/"compact-business-boundaries.json"
with out.open("xb") as f:f.write(b)
with (B/"compact-boundaries.py").open("xb") as f:f.write(sys.argv[1].encode())
assert fp(P.lstat())==fp(s)
pressure=o["phases"][1]
print(json.dumps({"pin":{"path":str(out),"bytes":len(b),"sha256":sha(b)},"pressure_history":pressure["history"],"pressure_confirmation":{k:pressure[k] for k in ("client_confirmed_transactions","confirmation_ended_ns","independent_client_confirmation","independent_final_confirmation_stage","verification_errors")}},sort_keys=True))
