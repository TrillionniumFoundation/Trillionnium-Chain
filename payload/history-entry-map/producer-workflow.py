import os,sys,subprocess,pathlib,json,hashlib
D=pathlib.Path('/private/tmp/chain-R1-history-4105-entry-map-20261114-v1')
D.mkdir(mode=0o700)
(D/'producer-workflow.py').write_text(sys.argv[1])
G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git';H='2a86462a1ab20c68151719ba4635e3c294391e64'
p='.github/workflows/pon-priority-acceptance.yml'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
r=subprocess.run(['/usr/bin/git','--git-dir='+G,'ls-tree',H,'--',p],env=e,capture_output=True,timeout=30,check=True)
(D/'ls-tree.stdout').write_bytes(r.stdout);(D/'ls-tree.stderr').write_bytes(r.stderr)
line=r.stdout.decode().strip();fields,name=line.split('\t',1);mode,typ,oid=fields.split()
if name!=p or typ!='blob':raise RuntimeError('unexpected tree')
q=subprocess.run(['/usr/bin/git','--git-dir='+G,'cat-file','blob',oid],env=e,capture_output=True,timeout=30,check=True)
if len(q.stdout)>1024*1024:raise RuntimeError('cap')
if hashlib.sha1(b'blob '+str(len(q.stdout)).encode()+b'\0'+q.stdout).hexdigest()!=oid:raise RuntimeError('blob')
(D/'workflow.yml.original').write_bytes(q.stdout);(D/'cat-file.stderr').write_bytes(q.stderr)
ls=q.stdout.decode().splitlines();hits=[i for i,l in enumerate(ls)if 'Execute 4105 real work blocks and paid public full sync'in l]
if len(hits)!=1:raise RuntimeError('exact step not unique')
i=hits[0];a=max(0,i-140);b=min(len(ls),i+85)
sel='\n'.join(str(j+1)+': '+ls[j]for j in range(a,b))+'\n';(D/'workflow-step-context.txt').write_text(sel)
obj={'source':H,'path':p,'git_blob':oid,'bytes':len(q.stdout),'sha256':hashlib.sha256(q.stdout).hexdigest(),'capture':str(D/'workflow.yml.original'),'selected_lines':[a+1,b],'matching_line':i+1,'tests_or_workflow_executed':False}
(D/'workflow-source.json').write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
print(json.dumps(obj));print(sel)
