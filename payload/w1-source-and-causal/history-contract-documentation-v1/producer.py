import os,sys,subprocess,json,hashlib,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/history-contract-documentation-v1');D.mkdir(mode=0o700)
(D/'producer.py').write_text(sys.argv[1])
H='2a86462a1ab20c68151719ba4635e3c294391e64';G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
args=['git','--git-dir='+G,'grep','-n','-I','-e','receive_public_page_from','-e','public_loopback_history','-e','loopback.*[Hh]istory','-e','[Hh]istory.*loopback',H,'--','docs/security','docs/development']
r=subprocess.run(args,env=e,capture_output=True,timeout=60);assert r.returncode in (0,1);assert len(r.stdout)<512*1024
(D/'source-search.stdout').write_bytes(r.stdout);(D/'source-search.stderr').write_bytes(r.stderr)
print(r.stdout.decode())
paths=[]
for line in r.stdout.decode().splitlines():
 p=line.split(':',2)[1]
 if p not in paths:paths.append(p)
assert len(paths)<=24
idx=[]
for p in paths:
 oid=subprocess.run(['git','--git-dir='+G,'rev-parse',H+':'+p],env=e,capture_output=True,check=True,timeout=30).stdout.decode().strip()
 b=subprocess.run(['git','--git-dir='+G,'cat-file','blob',oid],env=e,capture_output=True,check=True,timeout=30).stdout
 assert len(b)<2*1024*1024
 dest=D/p.replace('/','--');dest.write_bytes(b)
 idx.append({'source':H,'path':p,'git_blob':oid,'capture':str(dest),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
b=(json.dumps({'command':args,'exit_code':r.returncode,'files':idx},ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode();(D/'source-index.json').write_bytes(b)
print(json.dumps({'index':str(D/'source-index.json'),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'captured_count':len(paths)}))
