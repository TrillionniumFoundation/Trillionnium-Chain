import os,sys,json,hashlib,stat,datetime
from pathlib import Path
I=json.loads(sys.argv[1]);B=Path('/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1');D=B/'final-review-v1'
assert sys.flags.optimize==0
D.mkdir(mode=0o700)
def put(n,b):
 p=D/n
 with p.open('xb')as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
observed=[]
def read(pin):
 p=Path(pin['path']);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<2*1024*1024
  data=b''
  while True:
   chunk=os.read(fd,1048576)
   if not chunk:break
   data+=chunk
  assert fp(a)==fp(os.fstat(fd))==fp(p.lstat())
 finally:os.close(fd)
 assert len(data)==pin['bytes']and hashlib.sha256(data).hexdigest()==pin['sha256']
 observed.append((pin,fp(a)));return data
for row in I['sources']:
 raw=read(row['captured'])
 assert row['same_R1_H5DF']is True and row['H5DF_oid']==row['R1_oid']
 assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['H5DF_oid']
for pin in I['source_indices']:read(pin)
at=json.loads(read(I['corrected']));assert at['schema']=='h5df-exact-work-host-attribution-v2'
exact=json.loads(read(I['original_summary_pin']))
pressure=[];baseline=[]
for phase in at['phases']:
 for r in phase['replays']:
  assert len(r['packet_work'])==1 and r['measurement_failures']==0
  pw=r['packet_work'][0];w=pw['work']
  buckets=r['host_checkpoint_attribution']
  assert buckets['all_checkpoint_calls_attributed']is True
  h=next(x['calls']for x in buckets['buckets']if x['owner_phase']=='work')
  record={'phase_index':phase['phase_index'],'replay_index':r['replay_index'],'packet_id_hex':bytes(pw['packet_id']).hex(),'work_wall_ns':w['wall_ns'],'work_thread_cpu_ns':w['thread_cpu_ns'],'work_accepted':w['accepted'],'work_error':w['error_code'],'work_host_calls':h['calls_completed'],'work_host_thread_cpu_ns':h['thread_cpu_ns'],'work_host_summed_wall_ns':h['wall_ns'],'recorded_cpu_residual_outside_work_host_ns':w['thread_cpu_ns']-h['thread_cpu_ns']}
  if phase['phase_index']==0:baseline.append(record)
  else:
   assert phase['phase_index']==1
   record.update({'raw_pointer':'/phases/1/independent_history_page_replay/'+str(r['replay_index'])+'/native_import_observation','replay':r['replay_fields'],'work':w,'work_host':h,'work_end_minus_last_work_host_end_ns':w['ended_ns']-h['last_ended_ns'],'page_native_attribution':r['native_attribution']['page'],'packet_cpu_waits':[p['attribution']['cpu_waits']for p in r['native_attribution']['packets']]})
   pressure.append(record)
assert len(baseline)==7 and len(pressure)==2
assert pressure[0]['work_accepted']is True and pressure[1]['work_error']=='PUBLIC_REQUEST_DEADLINE'
assert [p['work_host_calls']for p in pressure]==[1099,338]
assert [p['recorded_cpu_residual_outside_work_host_ns']for p in pressure]==[3137933,936317]
assert [p['packet_id_hex']for p in pressure]==[p['packet_id_hex']for p in baseline[:2]]
scope={'scope':'current H5DF x64 selected original artifact plus immutable same-blob R1/H5DF source; not ARM or required protocol inference','whole_zip_verified':False,'original_elf_independently_hashed':False,'new_native_or_tests_executed':False,'new_network_calls':False,'source_or_git_ref_changed':False,'frozen_payload_changed':False}
compact={'schema':'h5df-w1-callchain-observation-facts-v1','original_report':at['original_report'],'source_identity':{'H5DF':'5df7ae6f482157c5f7fdcbcd52222117a965053f','R1':'2a86462a1ab20c68151719ba4635e3c294391e64'},'pressure':pressure,'baseline_work':baseline,'interpretation':'Host spans are nested same-calling-thread intervals in W1. Residual is not pure arithmetic CPU. No scheduler/cgroup/lock cause is assigned from wall minus CPU. Counts are packet-specific.',**scope}
pins=[]
pins.append(put('producer.py',sys.argv[2].encode()))
pins.append(put('compact-work-observations.json',(json.dumps(compact,sort_keys=True,indent=2)+'\n').encode()))
pins.append(put('review.md',I['review'].encode()))
summary={'schema':'h5df-w1-replay-readonly-review-v1','status':'CLOSED_STATIC_REVIEW_NO_ACCEPTANCE_CHANGE','sealed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_rows':I['sources'],'source_indices':I['source_indices'],'original_selected_facts':I['original_summary_pin'],'corrected_attribution':I['corrected'],'domain_evidence':I['domain'],'files':pins,'conclusions':['W1 FullLimb arithmetic and current progress callbacks execute synchronously on the importer thread; no hidden W1 worker CPU','Original 5ms verified-completion refill wait is unreachable during unfinished W1','Current fixture uses Exclusive independent Node and its own cold History domain; no shared-node wait during Work','Existing Work-attributed Host CPU is 63274464/66412397 ns and 19052498/19988815 ns for these pressure replays','Only small source-level FR-transpose and checked-A/B-rescan candidates; no measured improvement or proven 4s repair','Need actual phase/TID scheduler and phase-aligned cgroup data to assign wall delay'],**scope,'projection_correction':at['prior_projection_correction']}
pins.append(put('summary.json',(json.dumps(summary,sort_keys=True,indent=2)+'\n').encode()))
for pin,original_fp in observed:
 assert fp(Path(pin['path']).lstat())==original_fp
index=put('EVIDENCE_INDEX.json',(json.dumps({'schema':'readonly-review-files-v1','files':pins,'source_inputs':[p for p,_ in observed]},sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'status':summary['status'],'files':pins,'index':index,'scope':scope,'all10_runtime_fixture_blobs_same':True},sort_keys=True))
