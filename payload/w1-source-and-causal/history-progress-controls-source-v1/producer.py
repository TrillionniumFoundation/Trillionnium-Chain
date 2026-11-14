import os,sys,subprocess,json,hashlib,pathlib,re
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/history-progress-controls-source-v1');D.mkdir(mode=0o700)
(D/'producer.py').write_text(sys.argv[1])
H='2a86462a1ab20c68151719ba4635e3c294391e64';G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git';P='trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
oid=subprocess.run(['git','--git-dir='+G,'rev-parse',H+':'+P],env=e,check=True,capture_output=True,timeout=30).stdout.decode().strip()
b=subprocess.run(['git','--git-dir='+G,'cat-file','blob',oid],env=e,check=True,capture_output=True,timeout=30).stdout;assert len(b)<2*1024*1024
p=D/P.replace('/','--');p.write_bytes(b)
hits=[]
for n,s in enumerate(b.decode().splitlines(),1):
 if re.search(r'fn \w+',s)and any(x in s for x in('host','resource','deadline','checkpoint','progress','refill','loopback')):
  hits.append({'line':n,'source':s})
r={'head':H,'path':P,'git_blob':oid,'capture':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'relevant_function_hits':hits}
raw=(json.dumps(r,indent=2,sort_keys=True)+'\n').encode();(D/'source-index.json').write_bytes(raw)
print(json.dumps(r,indent=2));print(json.dumps({'index':str(D/'source-index.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
