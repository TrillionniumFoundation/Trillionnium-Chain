#!/usr/bin/env python3
"""Offline integrity and consistency checks of retained finite observations."""
from pathlib import Path
import base64,gzip,hashlib,json
ROOT=Path(__file__).resolve().parent
EXECUTED='58851cf923f6a8b7190b50228b30f3e82a682f9c'
FROZEN='4505a598d6ec2644a175e47398d4a5f3f054bc5e'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load_packages():
 manifest=json.loads((ROOT/'manifest.json').read_bytes());packages={}
 for item in manifest['packages']:
  raw=(ROOT/item['file']).read_bytes();assert len(raw)==item['bytes'] and sha(raw)==item['sha256']
  bundle=json.loads(gzip.decompress(raw));assert bundle['executed_source']==EXECUTED
  for field in ['private_hepta_source_included','private_owner_directories_included','private_keys_included','model_material_payload_included']:assert bundle[field] is False
  objects={}
  for file in bundle['files']:
   content=bundle['contents'][file['sha256']]
   data=content['data'].encode() if content['encoding']=='utf8' else base64.b64decode(content['data'])
   assert len(data)==file['bytes'] and sha(data)==file['sha256']
   objects[file['label']]=data
  packages[bundle['host']]=objects
 return manifest,packages
def options(argv,op):
 assert argv[1]==op and len(argv[2:])%2==0
 return dict(zip(argv[2::2],argv[3::2]))
def verify():
 manifest,p=load_packages()
 def obj(host,path):return json.loads(p[host][path])
 def native_source(r):
  assert r['source']=={'head':EXECUTED,'status':''} and r['source_unchanged'] and r['binary_unchanged']
  for k in ['independent_operators','public_discovery','long_term_custody','full_base_weights_transferred','production_activation','production_final_use']:assert r[k] is False
  assert r['qualification']=='HOLD_NO_GO'
 provider=obj('rog','serve-usb4-to-ai-v1/result.json');consumer=obj('ai395','receive-usb4-from-rog-v1/result.json')
 native_source(provider);native_source(consumer)
 assert provider['result']=='PASS_FINITE_PROVIDER_TERMINAL' and consumer['result']=='PASS_COLD_NATIVE_TWO_HOST_TRANSFER'
 assert provider['provider_exit']==0
 server_options=options(provider['provider_argv'],'serve')
 for k,v in {'--seconds':'12','--bounded-workers':'2','--max-served-bytes':'16777216','--max-connections':'16','--request-ms':'2000','--transport':'persistent-v2','--max-requests':'128','--max-requests-per-connection':'64','--bind':'10.77.0.1:39264'}.items():assert server_options[k]==v
 assert provider['planned_files']==consumer['planned_files']
 stats=json.loads(provider['provider_stdout']);assert stats['connections']==3 and stats['completed']==20 and stats['overloaded']==0
 transfers=consumer['transfers'];assert len(transfers)==3
 fetches=[c for c in consumer['commands'] if c['label'].startswith('fetch-')];assert len(fetches)==3
 files=[];intervals=[]
 for item,row,planned in zip(transfers,fetches,consumer['planned_files']):
  assert item['name']==planned['name'] and item['sha256']==planned['sha256']==item['fetch']['payload_sha256']==item['verify']['payload_sha256']
  assert item['bytes']==planned['bytes']==item['fetch']['downloaded_bytes']==item['verify']['bytes']
  assert item['fetch']['downloaded_chunks']==planned['chunks'] and item['fetch']['cached_chunks']==item['fetch']['rejected_responses']==0
  assert item['fetch']['manifest']==planned['manifest']==item['verify']['manifest']
  cfg=options(row['argv'],'fetch')
  for k,v in {'--overall-ms':'3000','--request-ms':'2000','--parallelism':'1','--max-connections':'2','--max-response-bytes':'4194304','--transport':'persistent-v2','--max-requests':'64','--max-requests-per-connection':'64','--peers':'10.77.0.1:39264','--max-bytes':str(planned['bytes'])}.items():assert cfg[k]==v
  assert row['exit']==0 and row['controller_timeout'] is False and row['seconds']<3
  assert provider['provider_ready_unix_ns']<=row['started_unix_ns']<row['ended_unix_ns']<=provider['provider_ended_unix_ns']
  files.append(dict(name=item['name'],payload_bytes=item['bytes'],chunks=planned['chunks'],sha256=item['sha256'],manifest=planned['manifest'],native_response_bytes=item['fetch']['received_response_bytes'],fetch_process_seconds=row['seconds']))
  intervals.append({k:row[k] for k in ['label','pid','started_unix_ns','ended_unix_ns','seconds']})
 payload_bytes=sum(i['payload_bytes'] for i in files);response_bytes=sum(i['native_response_bytes'] for i in files)
 assert payload_bytes==1011315 and sum(i['chunks'] for i in files)==17 and response_bytes==stats['sent_response_bytes']==1012818
 failures=[]
 for label,chost,cpath,phost,ppath in [('desktop-to-ai395-wifi','desktop','forward/result.json','ai395','serve-forward/result.json'),('desktop-to-ai395-bridge','desktop','forward-br0/result.json','ai395','serve-forward-br0/result.json'),('rog-to-ai395-usb4','rog','receive-usb4-v1/result.json','ai395','serve-usb4-v1/result.json')]:
  c=obj(chost,cpath);s=obj(phost,ppath);native_source(c);native_source(s)
  assert c['result']=='FAIL' and c['transfers']==[] and len(c['commands'])==1
  command=c['commands'][0];assert command['exit']==1 and 'phase=connect elapsed_ms=2001' in command['stderr'] and 'connection timed out' in command['stderr']
  cfg=options(command['argv'],'fetch');assert cfg['--overall-ms']=='3000' and cfg['--request-ms']=='2000'
  assert options(s['provider_argv'],'serve')['--seconds']=='12' and s['provider_exit']==0
  counters=json.loads(s['provider_stdout']);assert counters['connections']==counters['request_attempts']==counters['sent_response_bytes']==0
  failures.append(dict(label=label,consumer_receipt_sha256=sha(p[chost][cpath]),provider_receipt_sha256=sha(p[phost][ppath]),native_error=command['stderr'],consumer_process_seconds=command['seconds'],native_payload_bytes=0,provider_response_bytes=0))
 model=obj('ai395','evidence/public-model-load-summary.json')
 assert model['result']=='PASS_RECEIVED_BYTES_MODEL_LOAD_AND_COLD_READBACK' and model['actual_retained_model_loaded'] and model['actual_new_forward_calls']==1
 assert model['gradient_steps']==model['optimizer_calls']==0 and model['cold_response_exact'] and model['reexecuted_after_recovery'] is False
 assert model['first_worker']['pid']!=model['cold_worker']['pid'] and model['first_worker']['exit_code']==model['cold_worker']['exit_code']==0
 assert model['native_receive_receipt_sha256']==sha(p['ai395']['receive-usb4-from-rog-v1/result.json'])
 for k in ['native_current_binding','production_final_use','production_activation','independent_quality_evaluation','full_hepta_daemon_restart_qualified','private_hepta_source_included','private_owner_state_included','private_keys_included']:assert model[k] is False
 stage_r=obj('rog','staging-upload-v1/report.json');stage_a=obj('ai395','staging-upload-v1/report.json')
 assert stage_r['result']==stage_a['result']=='PASS_PINNED_BYTES_STAGED' and stage_r['native_cell_transfer'] is False and stage_a['native_cell_transfer'] is False
 assert stage_r['temporary_private_key_removed'] and stage_r['server_closed'] and stage_r['ended_unix_ns']<provider['provider_spawn_before_unix_ns']
 rdep=obj('rog','evidence/sparse-postbuild-verification/actual-rust-dep-info-inputs.json');adep=obj('ai395','evidence/actual-cell-source-inputs.json')
 rinputs={i['path']:(i['git_blob'],i['sha256']) for i in rdep['git_bound_inputs']};ainputs={i['path']:(i['git_blob'],i['sha256']) for i in adep['inputs']};assert rinputs==ainputs and len(rinputs)==96
 correspondence_raw=(ROOT/'source-correspondence.json').read_bytes();assert sha(correspondence_raw)==manifest['source_correspondence_sha256']
 cor=json.loads(correspondence_raw);assert cor['executed_source']==EXECUTED and cor['compared_frozen_source']==FROZEN and cor['comparison_only'] and cor['experiment_relabelled'] is False
 assert cor['all_recorded_repository_inputs_identical'] and cor['all_build_configuration_blobs_identical'] and cor['recorded_repository_inputs']==96 and cor['build_configuration_count']==29
 assert {i['path']:i['executed_git_blob'] for i in cor['inputs']}=={path:v[0] for path,v in rinputs.items()}
 assert {i['path']:i['git_blob'] for i in adep['build_configuration']}=={i['path']:i['executed_git_blob'] for i in cor['build_configuration']}
 preparation=[]
 for label in ['evidence/build.json','evidence/sparse-build/build.json','evidence/sparse-build-v2/build.json']:
  r=obj('rog',label);assert r['result']=='FAIL';preparation.append(dict(label=label,original_sha256=sha(p['rog'][label]),error=r['error']))
 return dict(schema='cell-public-continuation-summary-v1',result='PASS_RETAINED_OBSERVATIONS_AND_SOURCE_CORRESPONDENCE',executed_source=EXECUTED,compared_frozen_source=FROZEN,experiment_relabelled=False,operator_scope='same-operator-two-physical-hosts-private-USB4',native_protocol='persistent-v2',successful_native_payload_bytes=payload_bytes,successful_native_chunks=17,native_response_bytes=response_bytes,native_cached_chunks=0,native_rejected_responses=0,provider_stats=stats,provider_process={k:provider[k] for k in ['provider_pid','provider_spawn_before_unix_ns','provider_spawn_after_unix_ns','provider_ready_unix_ns','provider_ended_unix_ns']},fetch_processes=intervals,all_fetches_overlap_original_twelve_second_provider=True,provider_native_seconds=12,per_file_native_overall_ms=3000,native_request_ms=2000,files=files,retained_native_failures=failures,retained_preparation_failures=preparation,initial_preparation_text_receipts=['initial-bundle-preparation.log','initial-preflight-preparation.log'],model_public_summary=model,staging_counted_as_native_cell_transfer=False,utc_barrier_wait_counted_as_native_cell_transfer=False,two_hosts_actual_git_input_sets_identical=True,actual_git_input_count=96,frozen_candidate_configuration_blobs_identical=29,outside_compared_closure_changes=cor['outside_compared_closure_changes'],private_hepta_source_included=False,private_owner_directories_included=False,private_keys_included=False,model_material_payload_included=False,production_activation=False,production_final_use=False,independent_operators=False,public_discovery=False,long_term_custody=False,full_base_weights_transferred=False,qualification='HOLD_NO_GO')
if __name__=='__main__':print(json.dumps(verify(),sort_keys=True,indent=2))
