import subprocess,json,gzip,collections,pathlib
import argparse
HERE=pathlib.Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--repository',type=pathlib.Path,default=HERE.parents[1]);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
R=args.repository.resolve();O=args.output.resolve();O.mkdir(parents=True,exist_ok=True)
if O==HERE:raise SystemExit('Refuse to overwrite frozen evidence')

def git(*a):return subprocess.check_output(['git',*a],cwd=R).decode()
old=json.loads(gzip.decompress((R/'evidence/source-development-freeze-20261103/owner-discovery.json.gz').read_bytes()))
known={x['blob'] for x in old['variants']}
base=old['base'];inv=json.loads(git('show',base+':config/portability-inventory-v1.json'));paths=[x['path'] for x in inv['packages'] if x['module'] in ['M00','M04','M10']]
known.update(l.split()[2] for l in git('ls-tree','-r',base,'--',*paths).splitlines())
refs=json.loads(gzip.decompress((HERE/'heads.json.gz').read_bytes()))
new={}; inventories={};missing=[]
for i,(sha,ref) in enumerate(refs):
 line=git('ls-tree',sha,'config/portability-inventory-v1.json').strip()
 if not line:missing.append(ref);continue
 blob=line.split()[2]
 if blob not in inventories: inventories[blob]=json.loads(git('cat-file','blob',blob))
 packages=[p for p in inventories[blob].get('packages',[]) if p['module'] in ['M00','M04','M10']]
 for line in git('ls-tree','-r',sha,'--',*[p['path'] for p in packages]).splitlines():
  meta,path=line.split('\t');bid=meta.split()[2]
  if not path.endswith('.rs') or bid in known:continue
  owner=[p['module'] for p in packages if path.startswith(p['path'].rstrip('/')+'/')]
  v=new.setdefault(bid,{'blob':bid,'paths':set(),'modules':set(),'heads':[]});v['paths'].add(path);v['modules'].update(owner);v['heads'].append({'head':sha,'branch':ref,'inventory_blob':blob})
 if i%100==0:print(i,len(new),flush=True)
for v in new.values():v['paths']=sorted(v['paths']);v['modules']=sorted(v['modules'])
out={'heads':len(refs),'inventories':len(inventories),'missing_inventory':missing,'new_blob_count':len(new),'variants':list(new.values())}
(O/'source-delta.json').write_text(json.dumps(out,indent=2)+'\n');(O/'heads.json').write_text(json.dumps(refs,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k!='variants'}))
