import os,sys,subprocess,json,hashlib,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/server-history-progress-source-v1');D.mkdir(mode=0o700)
(D/'producer.py').write_text(sys.argv[1])
head='2a86462a1ab20c68151719ba4635e3c294391e64';db='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
idx=[]
for p in ('trillionnium/crates/trnm-pon-node/src/ingress.rs','trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_rejection.rs'):
 oid=subprocess.run(['git','--git-dir='+db,'rev-parse',head+':'+p],env=env,check=True,capture_output=True,timeout=30).stdout.decode().strip()
 r=subprocess.run(['git','--git-dir='+db,'cat-file','blob',oid],env=env,check=True,capture_output=True,timeout=30);b=r.stdout;assert len(b)<2*1024*1024
 target=D/p.replace('/','--');target.write_bytes(b);text=b.decode()
 idx.append({'source':head,'path':p,'git_blob':oid,'capture':str(target),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
 if p.endswith('ingress.rs'):
  for n,line in enumerate(text.splitlines(),1):
   if any(x in line for x in ('fn sync_host_kernel_owner','fn priced_sync_context','fn receive_public_page_from_before','host_kernel','control.resource','observe_host')):
    print(str(n)+':'+line)
 else:
  print('work_rejection: '+str(len(b))+' bytes')
b=(json.dumps(idx,indent=2,sort_keys=True)+'\n').encode();(D/'source-index.json').write_bytes(b)
print(json.dumps({'path':str(D/'source-index.json'),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'source':idx}))
