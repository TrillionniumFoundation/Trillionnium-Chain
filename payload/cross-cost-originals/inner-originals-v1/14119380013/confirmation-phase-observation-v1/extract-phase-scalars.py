import hashlib,json,os,pathlib,stat,sys,zipfile
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3")
A=int(sys.argv[1]);I=E/"inner-originals-v1"/str(A);O=I/"confirmation-phase-observation-v1"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def fid(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap):
 need(p.resolve()==p,"canonical")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,"bounded regular")
  raw=f.read(cap+1);b=os.fstat(f.fileno())
 need(fid(a)==fid(b)==fid(p.lstat()) and len(raw)==a.st_size,"stable bytes")
 return raw
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
need(A in (14119380013,14119000610) and not O.exists(),"fixed/create only");O.mkdir(mode=0o700)
put(O/"extract-phase-scalars.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
idx=json.loads(read(E/(str(A)+".index.json"),262144));pin=next(x for x in idx["files"] if x["path"]=="from-zero-native/confirmation/report.json")
zpath=E/(str(A)+".zip");zb=read(zpath,32*1024*1024);need(sha(zb)==idx["zip"]["sha256"],"closed ZIP")
with zipfile.ZipFile(zpath) as z:raw=z.read(pin["path"])
need(len(raw)==pin["bytes"] and sha(raw)==pin["sha256"],"actual report")
r=json.loads(raw)
def scalar(v):return v is None or isinstance(v,(str,bool,int,float))
def desc(v,depth=0):
 if scalar(v):return v if not isinstance(v,str) or len(v)<=360 else {"type":"string","length":len(v)}
 if isinstance(v,list):return {"type":"array","length":len(v),"first":desc(v[0],depth+1) if v else None}
 if depth>=2:return {"type":"object","keys":list(v)}
 return {k:desc(x,depth+1) for k,x in v.items()}
rows=[]
for i,p in enumerate(r["phases"]):
 scalars={k:v for k,v in p.items() if scalar(v)}
 shapes={k:desc(v) for k,v in p.items() if not scalar(v)}
 rows.append({"json_pointer":"/phases/"+str(i),"scalars":scalars,"structures":shapes})
out={"artifact_id":A,"report_member":pin,"top_scalars":{k:v for k,v in r.items() if scalar(v)},"phases":rows,"only_original_JSON_values_and_structure":True,"no_execution":True}
p=put(O/"phase-fields.json",jb(out))
print(json.dumps({"output":p,"phase_data":rows},sort_keys=True))
