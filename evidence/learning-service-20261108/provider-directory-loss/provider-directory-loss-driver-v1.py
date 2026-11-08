import os,json,hashlib,stat,subprocess,time
from pathlib import Path
os.umask(0o077)
work=Path('/home/qq/chain-real-iteration-20261108-8b4f0eedf006')
run=work/'artifacts/development-iteration-v1'
candidate=run/'trial/candidate'
native=run/'native-service'
binary=work/'bin/learning_service_round-fc406bad'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
assert sha(binary)=='fc406badb161bd9847b9aa3b7f5863018baae62b172467e2ae3a44317a76808a'
snapshot=work/'logs/pre-fault-backup-v1.json'
assert sha(snapshot)=='4b4bee2fab84c7a52bbf43b641300dda61273ac3ca1e207c7b921fc32047eac1'
saved=json.loads(snapshot.read_text())
assert saved['scope']=='read-only-evidence-backup-never-open-or-execute-copied-authority'
baseline=json.loads((run/'result.json').read_text())
expected=baseline['development_settlement']
main_sha=sha(run/'result.json');cold_sha=sha(work/'logs/integrated-cold-query-v1.stdout.log')
assert main_sha=='161a3bd2b194b2c8f6df598697cf2828c42df5e1657911bd42ca11e857175616'
assert cold_sha=='8ab71e7204b8a2baeb3fbf2ef58f280e6310a3fce6a01a602c8293c503905e06'
parent=work/'faults';parent.mkdir(mode=0o700,exist_ok=True)
fault=parent/'provider-directory-loss-v1';fault.mkdir(mode=0o700)
held_parent=fault/'retained-private';held_parent.mkdir(mode=0o700)
held=held_parent/'candidate'
def save(name,value):
 p=fault/name
 with p.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def pins(directory):
 s=directory.lstat();assert stat.S_ISDIR(s.st_mode)
 files=[]
 for p in sorted(directory.rglob('*')):
  st=p.lstat();assert stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
  if p.is_file():files.append({'path':str(p.relative_to(directory)),'bytes':st.st_size,'sha256':sha(p),'inode':st.st_ino,'device':st.st_dev,'mode':stat.S_IMODE(st.st_mode)})
 return {'inode':s.st_ino,'device':s.st_dev,'files':files,'content_identity':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
before_pins=pins(candidate)
for name,pin in baseline['candidate_operation']['observation']['pins'].items():
 p=candidate/name;assert p.stat().st_size==pin['bytes'] and sha(p)==pin['sha256']
def observe(label):
 command=[str(binary),'query',str(native)]
 start=time.monotonic_ns()
 stdout=fault/(label+'.stdout.json');stderr=fault/(label+'.stderr.log')
 with stdout.open('xb') as out,stderr.open('xb') as err:r=subprocess.run(command,stdout=out,stderr=err,cwd=work)
 receipt={'command':command,'returncode':r.returncode,'wall_ns':time.monotonic_ns()-start,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)}
 save(label+'-process.json',receipt)
 assert r.returncode==0,label
 v=json.loads(stdout.read_text())
 for key in ['operation_id','native_operation','intent_sha256','plan_sha256','evaluation_profile_sha256','provider_authority_id','task','claim','contract_digest']:
  assert v[key]==expected[key],key
 for key in ['current_branch_base_fee','historically_observed_base_fee']:
  assert v[key]==2000,key
 assert v['status']=='PAID_CURRENT_BRANCH' and v['locally_revoked'] is False
 assert v['improvement_bonus']==0 and v['anti_sybil_consensus_credit']==0 and v['model_state_unchanged'] is True
 assert v['resource_reservation']=='ORIGINAL_CONSUMPTION_RECORDED'
 original=expected['m12']['claims'][0];current=v['m12']['claims'][0]
 for key in ['claim','operation','contract_digest','resource_cap','resource_charge','declared_costs']:
  assert current[key]==original[key],key
 summary={k:v[k] for k in ['status','operation_id','native_operation','task','claim','contract_digest','intent_sha256','plan_sha256','evaluation_profile_sha256','current_branch_base_fee','historically_observed_base_fee','locally_revoked','resource_reservation','improvement_bonus','anti_sybil_consensus_credit','model_state_unchanged']}
 summary.update(resource_charge=current['resource_charge'],measurement_receipt=current['declared_costs']['measurement_receipt'],m12_sequence=v['m12']['sequence'],native_query=receipt)
 return summary
before=observe('before')
save('intent.json',{'schema':'chain-local-provider-directory-loss-intent-v1','candidate_original':str(candidate),'retained_private_path':str(held),'original_native_owner':str(native),'original_binary_sha256':sha(binary),'scope':'same-host-local-provider-output-directory-unavailable-only','before_directory_pins':before_pins,'before_native':before,'main_result_sha256':main_sha,'cold_query_sha256':cold_sha,'snapshot_receipt_sha256':sha(snapshot)})
renamed=False;restored=False;during=None
try:
 assert not held.exists()
 os.rename(candidate,held);renamed=True
 assert not candidate.exists()
 offline_pins=pins(held)
 assert offline_pins==before_pins
 save('directory-unavailable.json',{'original_path_absent':True,'retained_directory_pins':offline_pins,'scope':'local-directory-unavailable-not-independent-provider-or-host-loss'})
 during=observe('during-unavailable')
finally:
 if renamed:
  assert not candidate.exists() and held.stat().st_ino==before_pins['inode'] and held.stat().st_dev==before_pins['device']
  os.rename(held,candidate);restored=True
after_pins=pins(candidate);assert after_pins==before_pins
after=observe('after-restored')
assert sha(run/'result.json')==main_sha and sha(work/'logs/integrated-cold-query-v1.stdout.log')==cold_sha
result={'schema':'chain-local-provider-directory-loss-observation-v1','scope':'same-host-local-provider-output-directory-unavailable-only','before':before,'during':during,'after':after,'original_directory_restored':restored,'original_directory_inode_preserved':True,'directory_pins_before':before_pins,'directory_pins_after':after_pins,'initial_main_and_cold_query_bytes_unchanged':True,'same_original_native_owner_used':True,'copied_authority_opened_or_executed':False,'new_service_payment_or_model_dispatch':False,'independent_provider_outage_exercised':False,'host_disappearance_exercised':False}
save('result.json',result)
print(json.dumps({'provider_directory_loss_probe':'complete','before_status':before['status'],'during_status':during['status'],'after_status':after['status'],'current_base_fees':[v['current_branch_base_fee'] for v in [before,during,after]],'historical_base_fees':[v['historically_observed_base_fee'] for v in [before,during,after]],'resource_charge':after['resource_charge'],'original_inode':before_pins['inode'],'directory_identity':before_pins['content_identity'],'result_path':str(fault/'result.json'),'result_sha256':sha(fault/'result.json'),'original_main_unchanged':True,'original_directory_restored':True}),flush=True)
