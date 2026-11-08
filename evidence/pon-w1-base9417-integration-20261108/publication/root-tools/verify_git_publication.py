#!/usr/bin/env python3
"""Verify declared evidence bytes against a Git index or committed tree."""
import argparse,hashlib,io,json,pathlib,re,subprocess
ap=argparse.ArgumentParser()
ap.add_argument('--rev',required=True,help='Commit/tree reference, or INDEX for the current index')
ap.add_argument('--expected-new-inventory-sha256',required=True)
ap.add_argument('--output',required=True,type=pathlib.Path)
a=ap.parse_args()
assert re.fullmatch('[0-9a-f]{64}',a.expected_new_inventory_sha256)
specs=[
 ('evidence/pon-w1-four-gates-20261108','524bb438ef63bc5fb25ecba3a723e9bb64dc5d7dbf8560797c6788410c282dda',421),
 ('evidence/pon-w1-base62-integration-20261108','1a25fdb927a8ad7b7e980718cd85a1f0bced231b7f37df1ffa817ce142996d95',472),
 ('evidence/pon-w1-base96-integration-20261108','9c0c06ea019853aededd8e24475b34480ec05b45f7cc101a3e54d7a27f0b982a',1242),
 ('evidence/pon-w1-base9417-integration-20261108',a.expected_new_inventory_sha256,None)]
def ref(path):return (':'+path) if a.rev=='INDEX' else (a.rev+':'+path)
def objects(paths):
 raw=subprocess.run(['git','cat-file','--batch'],input=''.join(ref(p)+'\n' for p in paths).encode(),capture_output=True,check=True).stdout
 stream=io.BytesIO(raw);result={}
 for p in paths:
  h=stream.readline().decode().strip().split()
  assert len(h)==3 and h[1]=='blob',(p,h)
  b=stream.read(int(h[2]));assert stream.read(1)==b'\n'
  result[p]=(h[0],b)
 assert not stream.read()
 return result
def strict_pairs(pairs):
 d={}
 for k,v in pairs:
  assert k not in d,('duplicate JSON key',k)
  d[k]=v
 return d
manifest_paths=[prefix+'/publication-inventory.json' for prefix,_,_ in specs]
mo=objects(manifest_paths);expected={};groups=[]
for prefix,sha,count in specs:
 mp=prefix+'/publication-inventory.json';oid,b=mo[mp];assert hashlib.sha256(b).hexdigest()==sha,mp
 inv=json.loads(b,object_pairs_hook=strict_pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
 files=inv['files'];assert count is None or len(files)==count
 if count is None:assert inv['tested_source']=='4e007a87ceecbec8d265f6a70cfd71d512a514b5'
 seen=set()
 for f in files:
  name=f['path'];p=pathlib.PurePosixPath(name)
  assert not p.is_absolute() and '..' not in p.parts and '\n' not in name and '\0' not in name
  assert name!='publication-inventory.json' and name not in seen;seen.add(name)
  assert type(f['bytes']) is int and f['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',f['sha256'])
  full=prefix+'/'+name;assert full not in expected
  expected[full]={'bytes':f['bytes'],'sha256':f['sha256']}
 expected[mp]={'bytes':len(b),'sha256':sha}
 groups.append({'prefix':prefix,'members':len(files),'files_including_inventory':len(files)+1,'inventory_sha256':sha})
paths=sorted(expected);actual=objects(paths);blobs={};total=0
for p in paths:
 oid,b=actual[p];want=expected[p]
 assert len(b)==want['bytes'] and hashlib.sha256(b).hexdigest()==want['sha256'],p
 blobs[p]={'git_blob':oid,'bytes':len(b),'sha256':want['sha256']};total+=len(b)
prefixes=[p for p,_,_ in specs]
cmd=['git','ls-files','-z','--']+prefixes if a.rev=='INDEX' else ['git','ls-tree','-r','--name-only','-z',a.rev,'--']+prefixes
listed=set(x.decode() for x in subprocess.run(cmd,capture_output=True,check=True).stdout.split(b'\0') if x)
assert listed==set(paths),{'missing':sorted(set(paths)-listed),'extra':sorted(listed-set(paths))}
result={'schema':'TRNM-W1-EVIDENCE-GIT-BYTE-VERIFICATION1','revision':a.rev,'groups':groups,'file_count':len(paths),'total_bytes':total,'all_inventory_bytes_match_git_blobs':True,'no_extra_tracked_paths_in_four_packages':True,'blobs':blobs}
with a.output.open('x') as w:w.write(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('schema','revision','groups','file_count','total_bytes','all_inventory_bytes_match_git_blobs','no_extra_tracked_paths_in_four_packages')}))
