#!/usr/bin/env python3
"""Check exact retained pipeline observations; not independent execution attestation."""
from pathlib import Path
import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess

SOURCE='a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667'
TREE='b621fde199f0e52a8410f765fbda0d633a32d5ff'
CRATE='trillionnium/crates/trnm-data-availability/'
COMPONENTS={
 'cpv4':CRATE+'src/cell/pq/content.rs',
 'sealed_loader':CRATE+'src/cell/residency/sealed_loader.rs',
 'strict_tensor_reader':CRATE+'src/cell/tensor.rs',
 'tcp_peer':CRATE+'src/cell/bep52_peer.rs',
 'tcv2':CRATE+'src/cell/version_content.rs',
}

def require(ok, message):
 if not ok:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def unique(items):
 d={}
 for key,value in items:
  require(key not in d,'duplicate JSON field: '+key);d[key]=value
 return d
def load(path):
 require(path.is_file() and not path.is_symlink(),'not a regular retained input: '+str(path))
 require(path.stat().st_size<=8*1024*1024,'retained JSON/log too large')
 return json.loads(path.read_bytes(),object_pairs_hook=unique)
def zero(value):return type(value) is int and value==0
def file_sha(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def verify(root, records):
 receipts={}
 for label in ('pipeline-build','signed-sealed-pipeline'):
  p=records/(label+'.json'); r=load(p)
  require(r['schema']=='trnm-pq-native-command-v1','wrong receipt schema')
  require(r['status']=='command_succeeded' and zero(r['exit_code']),'command did not succeed: '+label)
  require(r['before']==r['after'],'changed source endpoints: '+label)
  b=r['before']
  require(b['candidate']==SOURCE and b['tested_commit']==SOURCE and b['tested_tree']==TREE and b['kind']=='head','wrong source: '+label)
  require(b['tracked_worktree_verified'] is True,'source bytes not verified')
  logname=r['log_file'];require(Path(logname).name==logname,'unsafe log name')
  raw=(records/logname).read_bytes()
  require(type(r['log_bytes']) is int and len(raw)==r['log_bytes'] and digest(raw)==r['log_sha256'],'changed retained log: '+label)
  require(r['whole_chain_quantum_security_qualified'] is False,'qualification promoted')
  receipts[label]=r
 build=receipts['pipeline-build']; run=receipts['signed-sealed-pipeline']
 require(build['argv']==['cargo','build','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-data-availability','--example','cell_signed_sealed_pipeline_v1'],'wrong build command')
 pin=load(records/'pipeline-binary.json'); require(pin['source']==SOURCE,'wrong binary pin source')
 require(run['argv']==[pin['path']],'wrong direct dispatch path')
 n=run['native_execution']
 require(n['schema']=='trnm-pinned-native-process-v1' and n['status']=='PINNED_AND_OBSERVED','native process not observed')
 require(n['child_reaped'] is True and zero(n['native_exit_code']),'native child did not complete')
 require(type(n['owned_pid']) is int and n['owned_pid']>0,'invalid owned PID')
 require(n['observation']['status']=='OBSERVED' and n['observation']['process']['pid']==n['owned_pid'],'wrong process binding')
 hashes=[pin['sha256'],n['expected_sha256'],n['dispatch_object']['sha256'],n['dispatch_object_after_sha256'],n['observation']['sha256']]
 require(len(set(hashes))==1 and re.fullmatch('[0-9a-f]{64}',hashes[0]),'inconsistent executable hashes')
 require(type(pin['bytes']) is int and pin['bytes']==n['dispatch_object']['bytes']==n['observation']['bytes'],'recorded binary size mismatch')
 # A later Cargo command may legitimately replace the same target path after
 # this already-reaped execution. Preserve that observation separately: the
 # original dispatch, post-dispatch and /proc executable pins must still agree.
 binary=Path(pin['path']);postcheck={'status':'UNAVAILABLE','bytes':None,'sha256':None}
 if binary.is_file() and not binary.is_symlink():
  size=binary.stat().st_size;actual=file_sha(binary)
  matched=size==pin['bytes'] and actual==hashes[0]
  postcheck={'status':'MATCHES_RECORDED_EXECUTION' if matched else 'REPLACED_SINCE_RECORDED_EXECUTION','bytes':size,'sha256':actual}
 require(n['dispatch_object']['device']==n['observation']['device'] and n['dispatch_object']['inode']==n['observation']['inode'],'observed dispatch identity mismatch')
 require(n['performance_measurement'] is False,'execution wrapper treated as benchmark')
 for key in ('build_provenance_verified_by_observer','descendant_execution_verified','entire_lifetime_image_verified'):
  require(n[key] is False,'unexpected strengthened execution claim: '+key)
 for key in ('libraries_sha256','loaded_memory_sha256','model_closure_sha256'):
  require(n[key] is None,'unexpected complete-image claim: '+key)

 output=load(records/'signed-sealed-pipeline.log')
 require(output['schema']=='trnm.cell-signed-sealed-component-pipeline.v1' and output['status']=='PASS_COMPONENT_PIPELINE' and output['stage']=='complete','pipeline incomplete')
 for key in ('final_use_granted','hepta_ready','hepta_started','wan_sla_observed'):
  require(output[key] is False,'scope was promoted: '+key)
 require(zero(output['gpu_operations']),'unexpected GPU operation')
 require(output['scope']=='native component wiring with synthetic F32 tensor and environment JSON','fixture scope changed')
 for label,path in COMPONENTS.items():
  raw=subprocess.check_output(['git','show',SOURCE+':'+path],cwd=root)
  require(digest(raw)==output['component_source_sha256'][label],'component source hash mismatch: '+label)
 example=subprocess.check_output(['git','show',SOURCE+':'+CRATE+'examples/cell_signed_sealed_pipeline_v1.rs'],cwd=root)
 require(digest(example)==output['example_source_sha256'],'example source hash mismatch')
 require(example.count(b'.verify_cached_at_with_pins(')==2,'retained verifier call sites changed')
 require(output['negative_controls']=={'corrupt_signature_error':'cell: PQ content signature','duplicate_model_bundle_error':'cell: content complete sealed version scopes'},'negative observations missing')

 network=output['network'];fetches=network['fetches'];usage=network['cumulative_usage']
 require(network['profile']=='cell-bep52-pinned-tcp-v1' and len(fetches)==2,'wrong native transfer profile/count')
 require(usage['completed_fetches']==2 and usage['connection_attempts']==2 and zero(usage['refused_connections']),'transfer completion accounting mismatch')
 endpoints=[]
 for index,row in enumerate(fetches,1):
  endpoint=row['endpoint'];require(re.fullmatch(r'127\.0\.0\.1:[0-9]+',endpoint),'not explicit loopback transport')
  require(1<=int(endpoint.rsplit(':',1)[1])<=65535,'bad endpoint port')
  endpoints.append(endpoint)
  require(row['client_error'] is None and row['server_error'] is None,'transfer error')
  require(row['supplying_peers']==[endpoint] and zero(row['cached_chunks']),'fixture did not use its actual native peer')
  require(row['downloaded_bytes']==row['payload_bytes'] and row['downloaded_chunks']>0,'incomplete payload')
  require(row['client_cumulative_usage']['completed_fetches']==index,'cumulative transfer mismatch')
 require(len(set(endpoints))==2,'expected two independent loopback listeners')
 require(fetches[-1]['client_cumulative_usage']==usage,'final cumulative counters changed')
 payload=sum(row['downloaded_bytes'] for row in fetches); chunks=sum(row['downloaded_chunks'] for row in fetches)
 require(payload==32930 and chunks==4,'fixture payload changed')
 require(output['publisher']['manifest_count']==2 and output['publisher']['declared_payload_bytes']==payload and output['publisher']['declared_chunks']==chunks,'publisher/transfer mismatch')
 require(output['consumer_readback']=={'actual_verified_chunk_references':chunks,'actual_verified_payload_bytes':payload,'attempted_scans':1},'complete readback accounting changed')
 sealed=output['sealed'];require(set(sealed)=={'model','environment'},'missing sealed closure')
 for role in ('model','environment'):
  files=sealed[role]['files'];require(len(files)==1,'unexpected sealed file count')
  require(files[0]['kernel_seal_bits'] & 15 == 15,'missing required kernel seals')
  require(re.fullmatch('[0-9a-f]{128}',files[0]['actual_post_seal_payload_sha512']),'missing full sealed payload hash')
  require(sealed[role]['snapshot_bytes']==files[0]['payload_bytes'],'sealed snapshot length mismatch')
 require(sum(sealed[k]['snapshot_bytes'] for k in sealed)==payload,'sealed closures do not cover complete payload')
 reader=output['native_readers']
 require(reader['tensor_count']==1 and reader['tensor_dtype']=='F32' and reader['tensor_shape']==[8193] and reader['tensor_file_payload_bytes']==32847,'strict tensor reader mismatch')
 require(reader['environment_json']=={'fixture':'native-component-pipeline','tensor_dtype':'F32','tensor_elements':8193},'environment reader mismatch')
 return {'schema':'trnm-current-pipeline-independent-verification-v1','result':'PASS','verified_utc':datetime.now(timezone.utc).isoformat(),
  'source':SOURCE,'tree':TREE,'receipts_verified':['pipeline-build','signed-sealed-pipeline'],'complete_source_endpoints_match':True,
  'native_process_status':n['status'],'native_exit_code':n['native_exit_code'],'child_reaped':True,'executable_sha256':hashes[0],
  'current_binary_fingerprint_verified':postcheck['status']=='MATCHES_RECORDED_EXECUTION','post_execution_path_observation':postcheck,
  'recorded_dispatch_and_observed_process_hashes_match':True,'native_bep52_fetches':len(fetches),'actual_payload_bytes':payload,'actual_chunk_references':chunks,
  'two_complete_sealed_closures_and_native_readers_observed':True,'negative_controls':output['negative_controls'],
  'component_source_hashes_match_exact_git_blobs':True,'synthetic_fixture':True,'real_model_efficacy_assessed':False,
  'final_use_granted':False,'hepta_started':False,'wan_sla_observed':False,'performance_improvement_measured':False,
  'independent_execution_authentication':False,'build_provenance_attested':False,'complete_lifetime_image_verified':False,
  'limits':'Checks retained observations and relationships. The original opened-dispatch/post-dispatch/proc executable pins agree; a separately reported later target-path fingerprint may differ or be unavailable. No independent execution/kernel/transport attestation, full library image, real model execution, WAN, deployment or cryptographic security theorem.',
  'whole_chain_pq_qualified':False,'production_activation':False}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',type=Path,required=True);parser.add_argument('--records',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args();root=args.root.resolve();out=args.output.resolve()
 require(not out.is_relative_to(root),'report must remain outside source checkout')
 report=verify(root,args.records.resolve());out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'result':report['result'],'source':SOURCE,'native_bep52_fetches':report['native_bep52_fetches'],'actual_payload_bytes':report['actual_payload_bytes'],'output':str(out)}))
