#!/usr/bin/env python3
import pathlib,hashlib,json,difflib
root=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
p=root/'launch_staged.py';b=p.read_bytes();s=b.decode()
old=" if cg:\n  cgp=pathlib.Path('/sys/fs/cgroup')/cg.lstrip('/');procs=cgp/'cgroup.procs';ev=cgp/'cgroup.events'\n  cgobs={'path':str(cgp),'exists':cgp.exists(),'procs':procs.read_text() if procs.exists() else None,'events':ev.read_text() if ev.exists() else None}\n  assert not cgobs['procs'] or not cgobs['procs'].strip(),(name,cgobs)\n"
new=" if cg:\n  cgp=pathlib.Path('/sys/fs/cgroup')/cg.lstrip('/');exists=cgp.exists()\n  cgobs={'path':str(cgp),'exists':exists,'subtree_procs':[],'events_before':None,'events_after':None}\n  if exists:\n   ev=cgp/'cgroup.events'\n   before=ev.read_text();cgobs['events_before']=before\n   evfields={}\n   for line in before.splitlines():\n    key,value=line.split();assert key not in evfields;evfields[key]=value\n   assert evfields.get('populated')=='0',(name,cgobs)\n   procs_paths=sorted(cgp.rglob('cgroup.procs'))\n   assert cgp/'cgroup.procs' in procs_paths,(name,str(cgp))\n   for procs in procs_paths:\n    raw=procs.read_text()\n    cgobs['subtree_procs'].append({'path':str(procs),'raw':raw})\n    assert not raw.strip(),(name,str(procs),raw)\n   after=ev.read_text();cgobs['events_after']=after\n   evfields={}\n   for line in after.splitlines():\n    key,value=line.split();assert key not in evfields;evfields[key]=value\n   assert evfields.get('populated')=='0',(name,cgobs)\n"
assert s.count(old)==1
s=s.replace(old,new)
assert s.count('TRNM-W1-C8-STAGED-LAUNCH-BINDING1')==1
s=s.replace('TRNM-W1-C8-STAGED-LAUNCH-BINDING1','TRNM-W1-C8-STAGED-LAUNCH-BINDING2')
old_scope='Current seven known C8 qualification jobs only; no assertion that the host has no other workloads or that every historical process was reaped'
new_scope='Current seven known C8 qualification jobs only; bounded cgroup-v2 observations assert no live processes in each present owned subtree. This does not establish zombie reaping, absence of other host workloads, or reaping/accounting for every historical process'
assert s.count(old_scope)==1;s=s.replace(old_scope,new_scope)
compile(s,str(root/'launch_staged_v2.py'),'exec')
with (root/'launch_staged_v2.py').open('x') as w:w.write(s)
delta=''.join(difflib.unified_diff(b.decode().splitlines(True),s.splitlines(True),fromfile='launch_staged.py',tofile='launch_staged_v2.py'))
with (root/'staged-launcher-review-correction.diff').open('x') as w:w.write(delta)
result={'schema':'TRNM-W1-C8-STAGED-PREEXEC-REVIEW-CORRECTION1','old_launcher':str(p),'old_sha256':hashlib.sha256(b).hexdigest(),'old_launcher_executed':False,'new_launcher':str(root/'launch_staged_v2.py'),'new_sha256':hashlib.sha256(s.encode()).hexdigest(),'reason':'The previous wrapper checked only direct cgroup.procs; the current owned-subtree precondition also needs descendants. The v2 wrapper requires cgroup.events populated=0 before and after a recursive empty cgroup.procs observation.','official_reference':'https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html','zombie_reaping_claimed':False,'source_changes':0,'test_argv_changes':0,'test_deadline_changes':0,'tests_executed':0}
with (root/'staged-launcher-review-correction.json').open('x') as w:w.write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
