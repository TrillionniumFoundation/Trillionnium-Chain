import hashlib,json,os,pathlib,stat,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3")
A=int(sys.argv[1])
need_ids={14119380013:(9851618,"d46ce31d5db37912f19115160d8b46e0bf32597fb3c4976a9c80b70bcc3df456"),14119000610:(9927038,"8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff")}
def need(v,m):
 if not v: raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,"regular")
  raw=f.read(128*1024*1024+1);after=os.fstat(f.fileno())
 need(len(raw)<=128*1024*1024 and before==after==p.lstat(),"stable bounded")
 return raw
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
need(A in need_ids,"fixed id")
I=E/"inner-originals-v1"/str(A)
O=I/"confirmation-structure-v1";need(not O.exists(),"create only");O.mkdir(mode=0o700)
put(O/"inspect-structure.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
idx=json.loads(read(E/(str(A)+".index.json")))
zb=read(E/(str(A)+".zip"));size,digest=need_ids[A];need(len(zb)==size and sha(zb)==digest,"whole ZIP")
name="from-zero-native/confirmation/report.json"
ent=next(x for x in idx["files"] if x["path"]==name)
need(ent["bytes"]<=128*1024*1024,"report cap")
with zipfile.ZipFile(E/(str(A)+".zip")) as z:raw=z.read(name)
need(len(raw)==ent["bytes"] and sha(raw)==ent["sha256"],"original report SHA")
r=json.loads(raw)
def outline(v,depth=0):
 if isinstance(v,dict):
  if depth>1:return {"type":"object","keys":list(v)}
  return {k:outline(x,depth+1) for k,x in v.items()}
 if isinstance(v,list):
  return {"type":"array","length":len(v),"first_element":outline(v[0],depth+1) if v else None}
 if isinstance(v,str) and len(v)>160:return {"type":"string","length":len(v),"prefix":v[:160]}
 return v
s={"artifact_id":A,"report":ent,"outline":outline(r),"no_code_executed":True}
b=(json.dumps(s,sort_keys=True,indent=2)+"\n").encode()
pin=put(O/"structure.json",b)
print(json.dumps({"structure":pin,"data":s},sort_keys=True))
