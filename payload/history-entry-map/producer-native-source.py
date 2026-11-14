import os,sys,pathlib,subprocess,json,hashlib
D=pathlib.Path('/private/tmp/chain-R1-history-4105-entry-map-20261114-v1')
with(D/'producer-native-source.py').open('x')as f:f.write(sys.argv[1])
H='2a86462a1ab20c68151719ba4635e3c294391e64';G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git';p='trillionnium/crates/trnm-pon-node/tests/ancestry_long_sync.rs'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
r=subprocess.run(['/usr/bin/git','--git-dir='+G,'ls-tree',H,'--',p],env=e,capture_output=True,check=True,timeout=30)
fields,name=r.stdout.decode().strip().split('\t',1);mode,typ,oid=fields.split()
if name!=p or typ!='blob':raise RuntimeError('tree')
q=subprocess.run(['/usr/bin/git','--git-dir='+G,'cat-file','blob',oid],env=e,capture_output=True,check=True,timeout=30)
if len(q.stdout)>1024*1024 or hashlib.sha1(b'blob '+str(len(q.stdout)).encode()+b'\0'+q.stdout).hexdigest()!=oid:raise RuntimeError('blob')
for n,b in [('native-ls-tree.stdout',r.stdout),('native-ls-tree.stderr',r.stderr),('native-cat-file.stderr',q.stderr),('ancestry_long_sync.rs.original',q.stdout)]:
 with(D/n).open('xb')as f:f.write(b)
v={'source':H,'path':p,'git_blob':oid,'bytes':len(q.stdout),'sha256':hashlib.sha256(q.stdout).hexdigest(),'capture':str(D/'ancestry_long_sync.rs.original'),'executed':False}
with(D/'native-source.json').open('x')as f:f.write(json.dumps(v,indent=2,sort_keys=True)+'\n')
print(json.dumps(v))
