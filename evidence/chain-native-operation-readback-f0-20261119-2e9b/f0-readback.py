#!/usr/bin/env python3
"""Read one complete original F0 artifact through unchanged pinned source readers."""
from __future__ import annotations
import ast, hashlib, json, pathlib, re, runpy, stat, sys, time, zipfile
BASE=pathlib.Path(__file__).resolve().parent
SOURCE=BASE/'readers-source'
HEAD='3db79eb2682ba3bcbbf33557c5eee3b67731028f'
TREE='4877dd4e945841e734a57234e89fb1eb0440805e'
RUN=44451798839
sys.dont_write_bytecode=True
sys.path.insert(0,str(SOURCE/'scripts'))
sys.path.insert(0,str(SOURCE/'scripts/ci'))
config_manifest=json.loads((BASE/'READERS_CONFIGS.json').read_text())
assert config_manifest['head']==HEAD
for row in config_manifest['files']:
 raw=(SOURCE/row['path']).read_bytes()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
import run_fixed_host_root_f0 as f0
def require(value,message):
 if not value:raise ValueError(message)
def digest(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def read(p):return f0.receipt(pathlib.Path(p),160*1024*1024)
def call_gate(fn,*args):
 try:return {'passed':True,'value':fn(*args),'refusal':None}
 except ValueError as error:return {'passed':False,'value':None,'refusal':str(error)}
def write(p,value):
 with pathlib.Path(p).open('x') as f:json.dump(value,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')
expected=None
for node in ast.parse((BASE/'prior-f0-readback.py').read_text()).body:
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ORIGINAL_READER_SHA256' for t in node.targets):expected=ast.literal_eval(node.value)
readers={str(pathlib.Path(m.__file__).resolve().relative_to(SOURCE)):digest(m.__file__) for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and pathlib.Path(m.__file__).resolve().is_relative_to(SOURCE) and pathlib.Path(m.__file__).suffix=='.py'}
require(readers==expected,'ORIGINAL_IMPORTED_READER_GRAPH_DIFFERS')
collection=BASE/'collection'
receipt=read(collection/'COLLECTION.json')
require(receipt['complete_download'] is True and receipt['run_id']==RUN and receipt['expected_head']==HEAD,'COMPLETE_ORIGINAL_DOWNLOAD_REQUIRED')
provider=read(collection/'run.stdout')
require(provider['id']==RUN and provider['head_sha']==HEAD and provider['status']=='completed','PROVIDER_EXACT_COMPLETED_HEAD_REQUIRED')
artifacts=read(collection/'artifacts.stdout')['artifacts']
require(len(artifacts)==1,'ONE_ORIGINAL_F0_ARTIFACT_REQUIRED')
artifact=artifacts[0];archive=collection/('artifact-'+str(artifact['id'])+'.zip');root=collection/('artifact-'+str(artifact['id']))
with zipfile.ZipFile(archive) as zipped:
 entries=zipped.infolist();names=[x.filename for x in entries]
 require(len(names)==len(set(names)) and sum(x.file_size for x in entries)<512*1024*1024,'ARCHIVE_ROSTER_OR_EXPANSION')
 for entry in entries:
  require(not pathlib.Path(entry.filename).is_absolute() and (root/entry.filename).resolve().is_relative_to(root) and not stat.S_ISLNK(entry.external_attr>>16),'ARCHIVE_PATH')
 inventory=read(root/'artifact-files.json')
 require(inventory['all_files_retained'] is True and inventory['errors']==[],'INCOMPLETE_ORIGINAL_INVENTORY')
 require(set(names)=={x['path'] for x in inventory['files']}|{'artifact-files.json'},'ORIGINAL_ARCHIVE_ROSTER_DIFFERS')
 for row in inventory['files']:
  p=root/row['path'];raw=zipped.read(row['path'])
  require(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],'ORIGINAL_MEMBER_CHANGED:'+row['path'])
 for prefix in ('','prepared/','execution/'):
  before,after=(read(root/(prefix+'source-'+moment+'.json')) for moment in ('before','after'))
  require(before==after and before['tested_commit']==HEAD and before['tested_tree']==TREE and before['tracked_worktree_verified'] is True,'SOURCE_BINDING:'+prefix)
 prepared=read(root/'prepared/prepared.json');execution=read(root/'execution/results.json');final=read(root/'finalization/result.json');report=read(root/'execution/raw/report.json')
 require(prepared['prepared'] is True and prepared['failure'] is None and prepared['runner_sha256']==digest(f0.__file__) and prepared['rust_source_control_selectors']==list(f0.SOURCE_CONTROLS) and prepared['inputs']==execution['inputs']==f0.INPUTS,'ORIGINAL_PREPARATION_CONTRACT')
 require(execution['prepared_sha256']==digest(root/'prepared/prepared.json') and execution['report_sha256']==digest(root/'execution/raw/report.json') and execution['binary']==prepared['binary'],'ORIGINAL_EXECUTION_BINDING')
 binary=root/'prepared/public_v3_multiprocess.bin';require(digest(binary)==prepared['binary']['sha256'] and binary.stat().st_size==prepared['binary']['bytes'],'ORIGINAL_NATIVE_ELF_BINDING')
 require(len(prepared['rust_source_controls'])==len(f0.SOURCE_CONTROLS)==7,'ORIGINAL_SEVEN_CONTROL_ROSTER')
 for i,control in enumerate(prepared['rust_source_controls']):
  require(control['complete_success'] is True and control['returncode']==0 and control['command'][2]==f0.SOURCE_CONTROLS[i],'ORIGINAL_PREPARATION_CONTROL_FAILURE')
 step=execution['step'];stdout=(root/'execution'/step['stdout']).read_text()
 require(step['command'][2]==f0.SELECTOR and 'test '+f0.SELECTOR+' ... ' in stdout,'ORIGINAL_NATIVE_SELECTOR_REQUIRED')
 rounds,packets=f0.f0_rounds(report),f0.f0_packets(report)
 require(len(rounds)==6 and len(packets)==42 and rounds==execution['all_planned_rounds']==final['denominator']['all_planned_rounds'] and packets==execution['all_planned_business_packets']==final['denominator']['all_planned_business_packets'],'ORIGINAL_DENOMINATOR_CHANGED')
 cgroup=report['controller_identity_before']['process']['cgroup']
 resources=f0.check_controller_resources(report,cgroup);require(resources==execution['controller_resource_summary'],'ORIGINAL_RESOURCE_READER_DIFFERS')
 gate=call_gate(f0.check_report,report,cgroup);slo=call_gate(f0.check_f0_placement_and_timing,report,cgroup);depletion=call_gate(f0.checked_depletion_samples,report['phases'][1])
 if not gate['passed']:require(execution['report_validation_failure']==gate['refusal'],'ORIGINAL_BUSINESS_REFUSAL_DIFFERS')
 business=all((gate['passed'],slo['passed'],step['returncode']==0,step['complete_success'] is True,execution['complete_success'] is True,final['complete_success'] is True,final['all_services_known_empty'] is True))
 result={'schema':'chain-fixed-root-f0-independent-current-readback-v1','run_id':RUN,'artifact_id':artifact['id'],'head':HEAD,'tree':TREE,'archive_sha256':digest(archive),'archive_bytes':archive.stat().st_size,'manifest_files_checked':len(inventory['files']),'original_reader_source_sha256':readers,'original_config_source':config_manifest,'readback_source_sha256':digest(__file__),'native_binary_sha256':digest(binary),'native_exit_code':step['returncode'],'original_preparation_controls':7,'original_business_gate':gate,'original_four_second_gate':slo,'original_numeric_depletion_gate':depletion,'confirmed_in_original_thirty_second_phases':sum(x['confirmed_inside_original_window'] for x in rounds),'planned_confirmations':6,'four_second_slo_successes':sum(x['four_second_slo_met'] for x in rounds),'planned_packet_exposures':42,'timely_network_ack_exposures':sum(x['timely_network_ack'] for x in packets),'unattempted_exposures':sum(x['observed_attempts']==0 for x in packets),'all_planned_rounds':rounds,'all_planned_business_packets':packets,'controller_resource_summary':resources,'all_services_known_empty':final['all_services_known_empty'],'business_pass':business,'full_physical_cost_closed':False,'production_activation':False,'unknown_cost_dimensions':['compiler/dependency acquisition CPU','concurrent whole-system RSS','physical storage I/O','storage byte-seconds','physical network bytes','GPU activity','energy','provider charges']}
 write(BASE/'f0-independent-readback.json',result)
 profile=runpy.run_path(str(BASE/'prior-cost-profile.py'))['profile'](archive.read_bytes(),RUN,HEAD)
 write(BASE/'current-cost-profile.json',{'schema':'chain-original-current-f0-cost-readback-v1','scope':'Exact unchanged prior cost reader; overlapping nested measurements are not additive; actual work denominators retained','full_physical_cost_closed':False,'run':profile})
 print(json.dumps({'evidence_readback':'VERIFIED','business_pass':business,'run_id':RUN,'head':HEAD,'original_window':str(result['confirmed_in_original_thirty_second_phases'])+'/6','scheduled_four_second':str(result['four_second_slo_successes'])+'/6','timely_ack':str(result['timely_network_ack_exposures'])+'/42','native_exit':step['returncode'],'business_gate':gate,'scheduled_gate':slo,'depletion_gate':depletion,'cleanup':final['all_services_known_empty'],'cost_profile':True}),flush=True)
