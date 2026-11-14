import os,sys,json,hashlib,zipfile,stat,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/cpu-distribution-v1')
D.mkdir(mode=0o700)
(D/'shape-producer.py').write_text(sys.argv[1])
E=pathlib.Path('/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1')
specs=[('head','14117751904.zip','b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8'),('prospective','14117403147.zip','2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a')]
out=[]
def shp(x):
 if isinstance(x,dict):return {k:({'type':'object','keys':list(v)} if isinstance(v,dict) else {'type':'array','n':len(v),'first':list(v[0]) if v and isinstance(v[0],dict) else (v[:3] if len(v)<30 else None)} if isinstance(v,list) else v) for k,v in x.items()}
 return x
for mode,name,h in specs:
 p=E/name
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno()); assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<20*1024*1024
  raw=f.read(); assert hashlib.sha256(raw).hexdigest()==h
  f.seek(0)
  with zipfile.ZipFile(f) as z:
   for kind in ('original','fresh'):
    member='fresh-service/'+kind+'/report.json'
    info=z.getinfo(member); assert info.file_size<32*1024*1024
    b=z.read(member); j=json.loads(b)
    for i,phase in enumerate(j['phases']):
     out.append({'mode':mode,'variant':kind,'phase_index':i,'member':member,'report_bytes':len(b),'report_sha256':hashlib.sha256(b).hexdigest(),'phase':shp(phase),'service':shp(phase.get('service',{}))})
  bstat=os.fstat(f.fileno()); c=os.lstat(p); assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(bstat.st_dev,bstat.st_ino,bstat.st_size,bstat.st_mtime_ns,bstat.st_ctime_ns)==(c.st_dev,c.st_ino,c.st_size,c.st_mtime_ns,c.st_ctime_ns)
p=D/'original-phase-fields.json'; b=(json.dumps(out,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode(); p.write_bytes(b)
print(json.dumps({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
for r in out[:2]:print(json.dumps(r,ensure_ascii=False,sort_keys=True))
