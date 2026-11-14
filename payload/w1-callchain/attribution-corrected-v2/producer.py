import os,sys,json,hashlib,stat,subprocess
from pathlib import Path
B=Path('/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1')
D=B/'attribution-corrected-v2';D.mkdir(mode=0o700)
def put(n,b):
 p=D/n
 with p.open('xb')as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
put('producer.py',sys.argv[1].encode())
report_path=Path('/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1/selected-v1/members/from-zero-native/confirmation/report.json')
with report_path.open('rb')as f:
 a=os.fstat(f.fileno());raw=f.read();b=os.fstat(f.fileno())
assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
assert len(raw)==13555781 and hashlib.sha256(raw).hexdigest()=='8b222dc0c57d1995dc2b33332d42cd7686078e5defa7e847abdd62816b40aaee'
r=json.loads(raw);facts=[]
for phase_index,phase in enumerate(r['phases']):
 replays=[]
 for replay_index,replay in enumerate(phase['independent_history_page_replay']):
  o=replay['native_import_observation']
  replays.append({'replay_index':replay_index,'replay_fields':{k:v for k,v in replay.items()if k!='native_import_observation'},'packet_work':[{'packet_index':packet['packet_index'],'packet_id':packet['packet_id'],'work':next(x for x in packet['phases']if x['phase']=='work')}for packet in o['packets']],'host_checkpoint_attribution':o.get('host_checkpoint_attribution'),'native_attribution':o.get('native_attribution'),'measurement_failures':o['measurement_failures']})
 facts.append({'phase_index':phase_index,'mode':phase.get('mode'),'replays':replays})
report_pin={'path':str(report_path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
allfacts={'schema':'h5df-exact-work-host-attribution-v2','original_report':report_pin,'phases':facts,'prior_projection_correction':{'path':str(B/'measurement-excerpts-v1/exact-work-host-attribution.json'),'problem':'projection variable p was shadowed by a phase dict, causing invalid original_report.path; worker_count projection used absent key; original bytes remain preserved and are not relied upon','raw_report_unchanged':True}}
p=put('exact-work-host-attribution.json',(json.dumps(allfacts,sort_keys=True,indent=2)+'\n').encode())
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
cmd=['/usr/bin/git','--git-dir=/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git','grep','-n','-E','remote_history_cpu_domain|cold_remote_history_epoch','5df7ae6f482157c5f7fdcbcd52222117a965053f','--','trillionnium/crates/trnm-pon-node/src']
q=subprocess.run(cmd,capture_output=True,timeout=30,env=env)
gp=put('history-domain-grep.stdout',q.stdout);ep=put('history-domain-grep.stderr',q.stderr);assert q.returncode==0
summary={'files':[p,gp,ep],'grep_argv':cmd,'grep_exit':q.returncode,'pressure':facts[1],'baseline_work':[x['packet_work']for x in facts[0]['replays']]}
put('summary.json',(json.dumps({'files':[p,gp,ep],'grep_argv':cmd,'grep_exit':q.returncode},indent=2)+'\n').encode())
print(json.dumps(summary,sort_keys=True))
