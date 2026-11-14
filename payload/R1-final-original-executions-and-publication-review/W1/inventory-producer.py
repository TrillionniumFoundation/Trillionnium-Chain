import pathlib,os,stat,hashlib,json,datetime
P=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root/R1-original-w1-v2-controls-linux-v1")
assert P.resolve(strict=True)==P
def sig(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def inv():
 f={};d={}
 for root,dirs,files in os.walk(P,followlinks=False):
  for n in dirs:
   p=pathlib.Path(root)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode);d[str(p.relative_to(P))]=sig(s)
  for n in files:
   p=pathlib.Path(root)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;f[str(p.relative_to(P))]=sig(s)
 return {"files":f,"dirs":d}
a=inv();rows=[];total=0
assert len(a["files"])<=128
for name,ver in sorted(a["files"].items()):
 p=P/name;assert p.resolve(strict=True)==p and ver[4]<=65536
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as f:
  assert sig(os.fstat(f.fileno()))==ver;b=f.read(ver[4]+1);assert sig(os.fstat(f.fileno()))==ver
 assert len(b)==ver[4] and sig(p.lstat())==ver;b.decode("utf-8")
 total+=len(b);assert total<=2*1024*1024
 rows.append({"path":str(p),"relative_path":name,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"version":ver,"origin":{"host":"rog","path":str(p)}})
assert inv()==a
s=next(r for r in rows if r["relative_path"]=="summary.json");assert (s["bytes"],s["sha256"])==(7754,"edb1e9f855450b5f330332b5dbdae17ea6546ad75d2f1dff81106b9b2382ee71")
print(json.dumps({"schema":"trnm-R1-W1-originals-closed-inventory-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"directory":str(P),"files":rows,"count":len(rows),"bytes":total,"directory_unchanged":True,"directories":a["dirs"],"source_or_git_or_test_actions":False}),flush=True)
