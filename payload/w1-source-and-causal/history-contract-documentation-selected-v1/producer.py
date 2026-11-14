import os,sys,subprocess,json,hashlib,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/history-contract-documentation-selected-v1');D.mkdir(mode=0o700)
(D/'producer.py').write_text(sys.argv[1])
H='2a86462a1ab20c68151719ba4635e3c294391e64';G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
specs=[('HISTORY_W1_SHARED_CPU_HOST_20261027.md',[(1,92)]),('REMOTE_SYNC_W1_HOST_GUARD.md',[(1,28),(129,169)]),('W1_P0_P1_STRICT_INTEGRATION_20261027.md',[(1,53)]),('PUBLIC_POOL_INTAKE_V3.md',[(1058,1094)])]
idx=[]
for name,ranges in specs:
 p='docs/protocol/pon-nakamoto-v1/details/'+name
 oid=subprocess.run(['git','--git-dir='+G,'rev-parse',H+':'+p],env=e,capture_output=True,check=True,timeout=30).stdout.decode().strip()
 b=subprocess.run(['git','--git-dir='+G,'cat-file','blob',oid],env=e,capture_output=True,check=True,timeout=30).stdout;assert len(b)<1024*1024
 dest=D/(name+'.original');dest.write_bytes(b);lines=b.decode().splitlines()
 entry={'source':H,'path':p,'git_blob':oid,'capture':str(dest),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'read_ranges':ranges}
 idx.append(entry)
 chunks=[]
 for first,last in ranges:
  chunks.append('\n'.join(str(i+1)+': '+s for i,s in enumerate(lines)if first<=i+1<=last))
 text='\n\n'.join(chunks)+'\n';(D/(name+'.selected.txt')).write_text(text)
 print(name+'\n'+text)
raw=(json.dumps(idx,indent=2,sort_keys=True)+'\n').encode();(D/'source-index.json').write_bytes(raw)
print(json.dumps({'index':str(D/'source-index.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
