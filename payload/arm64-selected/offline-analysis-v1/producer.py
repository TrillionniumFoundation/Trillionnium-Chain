import hashlib,json,os,stat,sys
from pathlib import Path
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
src=base/'selected-resume-001';out=base/'offline-analysis-v1';out.mkdir(mode=0o700)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n=None,h=None):
 p=Path(p);a=p.lstat()
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size>32*1024*1024:raise ValueError('SOURCE_TYPE')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')as f:
  if fp(a)!=fp(os.fstat(f.fileno())):raise ValueError('OPEN')
  b=f.read(a.st_size+1)
  if fp(a)!=fp(os.fstat(f.fileno())):raise ValueError('FD_CHANGED')
 if fp(a)!=fp(p.lstat())or len(b)!=a.st_size or(n is not None and len(b)!=n)or(h is not None and hashlib.sha256(b).hexdigest()!=h):raise ValueError('PIN')
 return b
def pairs(kv):
 d={}
 for k,v in kv:
  if k in d:raise ValueError('DUPLICATE_KEY')
  d[k]=v
 return d
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('NONFINITE')))
def put(name,v):
 b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();p=out/name
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
summary=parse(read(src/'summary.json',22217,'721e28940cd1735b304104886fc2b553ba7df62e72b80d810ba350e99fb6daa6'))
idx=parse(read(summary['selected_members']['path'],summary['selected_members']['bytes'],summary['selected_members']['sha256']))
raws={}
for r in idx['files']:
 raws[r['path']]=read(r['original']['path'],r['bytes'],r['sha256'])
if len(raws)!=25:raise ValueError('SELECTED_ROSTER')
m=parse(raws['from-zero-native/manifest.json']);r=parse(raws['from-zero-native/confirmation/report.json'])
def shape(x,depth=0):
 if isinstance(x,dict):
  return {k:shape(v,depth+1)for k,v in x.items()}if depth<2 else {'type':'dict','keys':list(x)}
 if isinstance(x,list):return {'type':'list','length':len(x),'first':shape(x[0],depth+1)if x else None}
 if isinstance(x,str)and len(x)>240:return {'type':'str','bytes':len(x.encode())}
 return x
value={'manifest':shape(m),'report':shape(r),'processes':{},'source':parse(raws['source.json']),'host':{}}
for path,b in raws.items():
 if path.endswith('/process.json'):value['processes'][path]=parse(b)
 if path.startswith('from-zero-native-host/')and path.endswith('.json'):value['host'][path]=shape(parse(b))
value['phase_shapes']=[{'index':i,'shape':shape(v)}for i,v in enumerate(r.get('phases',[]))]
pin=put('structure.json',value)
with(out/'producer.py').open('xb')as f:f.write(sys.argv[1].encode())
print(json.dumps({'structure':pin,'manifest_keys':list(m),'manifest_files_type':type(m.get('files')).__name__,'manifest_native_shape':shape(m.get('native')),'report_keys':list(r),'phase_shapes':value['phase_shapes'],'processes':value['processes'],'source':value['source']},sort_keys=True))
