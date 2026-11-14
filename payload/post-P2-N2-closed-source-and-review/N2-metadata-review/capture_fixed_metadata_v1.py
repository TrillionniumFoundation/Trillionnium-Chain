#!/usr/bin/env python3
import os,sys,stat,json,hashlib,subprocess,time,traceback
from pathlib import Path
D=Path('/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git')
O=Path('/private/tmp/chain-N2-metadata-integration-review-20261114-v1')
heads={'N':'5a4b7fe8de1adce803184f262fd9f704ead1930c','N2':'096c6b5f9b952c49389fd975515744074ba61317','P2':'1e54c4ff66a92827c83bea8715f59f6b299e98cf'}
paths=['config/pon/hash-use-contract-v1.json','scripts/ci/hash_use_contract.py','config/pon/pq-cross-branch-corpus-v1.json','trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs']
env=os.environ.copy();env.update(GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',GIT_PAGER='cat',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
for k in list(env):
 if k.startswith('GIT_TRACE')or k=='GIT_CURL_VERBOSE':env.pop(k,None)
env.update(GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
if sys.flags.optimize or D.resolve()!=D or not D.is_dir()or os.path.lexists(O):raise ValueError('fixed Git/create-only evidence')
O.mkdir(mode=0o700);(O/'sources').mkdir();(O/'diffs').mkdir();(O/'commands').mkdir()
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def put(p,b):
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('evidence readback')
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
put(O/'capture_fixed_metadata_v1.py',sys.argv[1].encode())
state={'schema':'trnm-N2-fixed-metadata-capture-v1','status':'HOLD','heads':heads,'paths':paths,'steps':[],'errors':[],'source_worktree_stage_Git_refs_or_network_written':False,'tests_run':False}
def run(label,args,input=None):
 start=time.time();argv=['/usr/bin/git','--git-dir='+str(D),'-c','protocol.allow=never',*args]
 try:r=subprocess.run(argv,input=input,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 except subprocess.TimeoutExpired as exc:
  out=exc.stdout or b'';err=exc.stderr or b'';code=124;timed=True
 else:out=r.stdout;err=r.stderr;code=r.returncode;timed=False
 if len(out)>16*1024*1024 or len(err)>1024*1024:raise ValueError('bounded Git output')
 row={'label':label,'argv':argv,'cwd':None,'exit':code,'timeout':timed,'elapsed_seconds':time.time()-start,'stdout':put(O/'commands'/(label+'.stdout'),out),'stderr':put(O/'commands'/(label+'.stderr'),err)}
 state['steps'].append(row)
 if code:raise ValueError('fixed Git read failed '+label)
 return out
try:
 trees={}
 for name,head in heads.items():
  raw=run(name+'-commit',['cat-file','commit',head])
  if len(raw)>65536 or hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=head:raise ValueError('commit identity')
  hdr=raw.split(b'\n\n',1)[0].decode();tree=[l[5:]for l in hdr.splitlines()if l.startswith('tree ')];parents=[l[7:]for l in hdr.splitlines()if l.startswith('parent ')]
  if len(tree)!=1:raise ValueError('tree header')
  trees[name]={'tree':tree[0],'parents':parents}
  if name=='N2'and (tree[0]!='aab22f6d1bdff4aa55a79a1e9136f14490c6b057'or parents!=[heads['N']]):raise ValueError('N2 ancestry/tree')
  if name=='P2'and not tree[0].startswith('2c0716'):raise ValueError('P2 tree prefix')
 state['identities']=trees
 run('N-N2-all-name-status',['diff','--no-ext-diff','--no-textconv','--no-renames','--name-status',heads['N'],heads['N2']])
 rows=[]
 for name,head in heads.items():
  listing=run(name+'-selected-ls-tree',['ls-tree','-z',head,'--',*paths])
  found={}
  for record in listing.split(b'\0'):
   if not record:continue
   left,path=record.split(b'\t',1);mode,kind,oid=left.decode().split();path=path.decode()
   if kind!='blob'or mode not in ['100644','100755']or path in found:raise ValueError('selected tree entry')
   found[path]=(mode,oid)
  if set(found)!=set(paths):raise ValueError('four selected paths missing')
  sizes=run(name+'-selected-object-sizes',['cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'],('\n'.join(found[x][1]for x in paths)+'\n').encode()).decode().splitlines()
  for path,size_line in zip(paths,sizes,strict=True):
   mode,oid=found[path];got,typ,n=size_line.split();n=int(n)
   if (got,typ)!=(oid,'blob')or n>4*1024*1024:raise ValueError('selected source cap/type')
   flat=path.replace('/','--')
   raw=run(name+'-'+flat,['cat-file','blob',oid])
   if len(raw)!=n or hashlib.sha1(b'blob '+str(n).encode()+b'\0'+raw).hexdigest()!=oid:raise ValueError('blob address')
   capture=put(O/'sources'/(name+'--'+flat+'.original'),raw)
   rows.append({'identity':name,'commit':head,'tree':trees[name]['tree'],'path':path,'mode':mode,'oid':oid,'bytes':n,'sha256':sha(raw),'capture':capture})
 for left,right in [('N','N2'),('P2','N2')]:
  raw=run(left+'-'+right+'-four-paths-diff',['diff','--binary','--full-index','--no-renames','--no-ext-diff','--no-textconv',heads[left],heads[right],'--',*paths])
  put(O/'diffs'/(left+'-to-'+right+'.patch'),raw)
  for path in paths:
   raw=run(left+'-'+right+'-'+path.replace('/','--')+'-diff',['diff','--binary','--full-index','--no-renames','--no-ext-diff','--no-textconv',heads[left],heads[right],'--',path])
   put(O/'diffs'/(left+'-to-'+right+'--'+path.replace('/','--')+'.patch'),raw)
 table=put(O/'source-table.json',js({'heads':heads,'identities':trees,'files':rows}))
 state.update(status='FIXED_METADATA_CAPTURED',source_table=table)
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
finally:
 summary=put(O/'capture-summary.json',js(state))
 print(json.dumps({'status':state['status'],'summary':summary,'source_table':state.get('source_table'),'identities':state.get('identities'),'errors':state['errors']}),flush=True)
sys.exit(0 if state['status']=='FIXED_METADATA_CAPTURED'else 1)
