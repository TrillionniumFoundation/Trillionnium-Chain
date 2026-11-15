"""Portable read-only audit of the fixed grouped owner campaign.

The --out argument is a new JSON file outside the source, campaign and validation
folders. Binding comes from the supplied validation directory's runner-bindings,
source-after, successful authority build result, and exact committed driver.
This audit makes additional post-campaign chain queries and reports them apart
from both campaign timing and K. No source, packet, ledger or prior result changes.
A PASS authenticates these local records under their stated host assumptions;
it is not a reproducible-build, real authorization or power-loss attestation.
"""
import argparse,hashlib,json,pathlib,re,resource,sqlite3,sys,time,subprocess,os
from collections import Counter
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo',required=True,type=pathlib.Path)
parser.add_argument('--campaign',required=True,type=pathlib.Path)
parser.add_argument('--out',required=True,type=pathlib.Path,help='new JSON file; create-only')
parser.add_argument('--source-sha',required=True)
parser.add_argument('--validation-dir',required=True,type=pathlib.Path)
args=parser.parse_args()
if not all(p.is_absolute() for p in [args.repo,args.campaign,args.out,args.validation_dir]):
    raise ValueError('ALL_PATHS_MUST_BE_ABSOLUTE')
ROOT=args.repo.resolve(strict=True)
OUT=args.campaign.resolve(strict=True)
VALIDATION=args.validation_dir.resolve(strict=True)
DEST=args.out.parent.resolve(strict=True)/args.out.name
SHA=args.source_sha
if re.fullmatch(r'[0-9a-f]{40}',SHA) is None:
    raise ValueError('SOURCE_SHA_FORMAT')
if not all(p.is_dir() for p in [ROOT,OUT,VALIDATION]):
    raise ValueError('INPUT_DIRECTORY_REQUIRED')
if any(DEST==p or p in DEST.parents for p in [ROOT,OUT,VALIDATION]):
    raise ValueError('OUTPUT_MUST_BE_OUTSIDE_SOURCE_CAMPAIGN_AND_VALIDATION')
if DEST.exists() or DEST.is_symlink():
    raise FileExistsError('AUDIT_OUTPUT_MUST_NOT_EXIST')
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from contract_wire import canonical,unique
from grouped_fresh_admission_wire_v0 import pon_hash,decode_body,material_commitments
from grouped_legal_strategy_v0 import independent_reference,REPRESENTATION
from experiments.grouped_cell_operator_v0 import input_commitment,statement_commitment

start=time.perf_counter_ns();cpu=time.process_time_ns();checks=[]
audit_children_before=resource.getrusage(resource.RUSAGE_CHILDREN)
step_calls=seed_calls=0
reference_started=False

def failure_record(kind,error,tb):
    # Preserve any observed work if a later check fails. The original traceback
    # remains authoritative and the interpreter still exits nonzero.
    reference=globals().get('reference_cost')
    record={'schema':'pon-grouped-owner-independent-audit-portable-v2',
        'status':'FAIL','source_commit':SHA,'campaign':str(OUT),
        'validation_directory':str(VALIDATION),'error_type':kind.__name__,
        'error':str(error),'checks':checks,
        'checks_passed':sum(c['passed'] for c in checks),
        'post_campaign_audit_chain_step_queries_known':step_calls,
        'post_campaign_audit_seed_queries_known':seed_calls,
        'reference_call_started':reference_started,
        'post_campaign_audit_reference_macs':reference.reference_macs if reference else None,
        'post_campaign_audit_reference_additions':reference.reference_additions if reference else None,
        'partial_counters_not_a_success_or_full_cost_claim':True,
        'whole_before_failure_report_wall_ns':time.perf_counter_ns()-start,
        'audit_process_cpu_ns':time.process_time_ns()-cpu,
        'source_and_historical_evidence_mutated':False,
        'chainwork_awarded':0,'production_activation':False}
    try:
        with DEST.open('x') as handle:
            json.dump(record,handle,sort_keys=True,indent=2,allow_nan=False)
            handle.write('\n')
    except OSError as preserve_error:
        print('Could not preserve create-only failure report: '+str(preserve_error),file=sys.stderr)
    sys.__excepthook__(kind,error,tb)
sys.excepthook=failure_record

def need(ok,name):
    checks.append({'check':name,'passed':bool(ok)})
    if not ok:raise AssertionError(name)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes(),object_pairs_hook=unique)
def public(i):
    seed=pon_hash(b'DEV-ONLY-GROUPED-OWNER-KEY',i.to_bytes(8,'big'))
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
def edverify(public_key,signature,message):
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature,message)
def claim_bytes(c):
    p=c['product'];raw=b''.join(bytes.fromhex(c[n]) for n in ['model_commitment','input_commitment','statement_commitment'])
    for name in ['router_outputs','logits']:
        rows=p[name];raw+=len(rows).to_bytes(8,'big')
        raw+=b''.join(x.to_bytes(8,'big',signed=True) for row in rows for x in row)
    for rows in [p['routes'],p['predictions'],*p['groups']]:
        raw+=len(rows).to_bytes(8,'big')+b''.join(x.to_bytes(8,'big') for x in rows)
    raw+=b''.join(p[n].to_bytes(8,'big') for n in ['useful_dense_macs','padded_macs','nonempty_expert_groups'])
    return raw
def fingerprint(wire,policy):
    c=wire['command']
    return pon_hash(b'pon-grouped-owner-submission-v0',policy,bytes.fromhex(wire['receiver']),
        bytes.fromhex(c['request_id']),bytes.fromhex(c['candidate']),claim_bytes(c['claim']),bytes.fromhex(c['proof_hex']))
def seal_frame(tag,*parts):
    return b'TRNM-GROUPED-FRESH-SEAL0\0'+len(tag).to_bytes(2,'big')+tag+b''.join(len(p).to_bytes(4,'big')+p for p in parts)
profile=hashlib.sha256(seal_frame(b'profile',b'pon-grouped-int257-sealed-research-v0',
    b'pon-routed-int257-grouped-research-v0',b'signed-i32-coeff-i64-accum-bias8-lowest-argmax',
    (64).to_bytes(2,'big'),(16).to_bytes(2,'big'))).digest()

r=read(OUT/'report.json');config=read(OUT/'config.json');prep=read(OUT/'owner/preparation.json')
need(r['status']=='PASS' and r['exact_committed_source_verified'] and not r['failures'],'exact_source_campaign_pass')
need(r['expected_source_sha']==SHA and r['source_before']['commit']==r['source_after']['commit']==SHA,'source_commit')
need(r['source_before']['tracked_tree_clean'] and r['source_after']['tracked_tree_clean'],'tracked_tree_clean_before_after')
for name,item in r['source_before']['relevant_sources'].items():
    need(item['tracked_at_head'] and item['matches_head_bytes'] and item['actual_sha256']==r['source_after']['relevant_sources'][name]['actual_sha256'],f'source_pin:{name}')
# Bind this run to the passed release artifact recorded by the caller's exact
# source validation. No local development-build path or binary hash is assumed.
request=read(OUT/'request.json')
runner=pathlib.Path(request['runner'])
need(runner.is_absolute() and runner==runner.resolve(strict=True),'canonical_runner_path')
binding=read(VALIDATION/'runner-bindings.json')
after=read(VALIDATION/'source-after.json')
validation_source=after['source']
need(after['status']=='PASS' and validation_source['schema']=='trnm-ci-source-v1'
     and validation_source['kind']=='head'
     and validation_source['tested_commit']==validation_source['candidate']==SHA
     and validation_source['tracked_worktree_verified'] is True,'validation_exact_source')
tested_tree=subprocess.check_output(['git','--no-replace-objects','rev-parse',SHA+'^{tree}'],cwd=ROOT,text=True).strip()
need(validation_source['tested_tree']==tested_tree,'validation_exact_tree')
driver_name='formal/pon-nakamoto-v1/experiments/validate_grouped_fresh_work_v0.py'
driver_committed=subprocess.check_output(['git','--no-replace-objects','show',SHA+':'+driver_name],cwd=ROOT)
need(sha(driver_committed)==sha((ROOT/driver_name).read_bytes())==after['driver_sha256'],'validation_driver_exact_bytes')
need(binding['status']=='PASS','validation_runner_binding_pass')
target_directory=pathlib.Path(binding['cargo_target_directory'])
need(target_directory.is_absolute() and target_directory==target_directory.resolve(strict=True),'canonical_cargo_target_directory')
expected_runner=target_directory/'release/examples/grouped_verification_authority_v0'
need(runner==expected_runner and runner==pathlib.Path(binding['artifacts']['authority']['path']),'validation_authority_runner_path')
artifact=binding['artifacts']['authority']
need(artifact['exists'] and artifact['executable'] and os.access(runner,os.X_OK)
     and runner.stat().st_size==artifact['bytes'],'validation_runner_size_and_executable')
need(sha(runner.read_bytes())==r['runner_sha256']==prep['runner_sha256']==artifact['sha256'],'runner_bytes')
build_result=read(VALIDATION/'authority-native-build.result.json')
need(build_result['label']=='authority-native-build' and build_result['status']=='PASS'
     and build_result['process_started'] and build_result['exit_code']==0
     and not build_result['timed_out'] and build_result['built_runner']==artifact,'validation_successful_authority_build')
build_log_name=pathlib.Path(build_result['log'])
need(not build_log_name.is_absolute() and len(build_log_name.parts)==1,'validation_build_log_relative_name')
build_log=(VALIDATION/build_log_name).read_bytes()
need(len(build_log)==build_result['log_bytes'] and sha(build_log)==build_result['log_sha256'],'validation_authority_build_log_bytes')
owned_sources=[
    'trillionnium/crates/trnm-pon-node/src/grouped_verification_authority_v0.rs',
    'trillionnium/crates/trnm-pon-node/examples/grouped_verification_authority_v0.rs',
    'trillionnium/crates/trnm-pon-node/tests/grouped_verification_authority_v0.rs',
    'formal/pon-nakamoto-v1/experiments/grouped_verification_authority_v0.py']
for name in owned_sources:
    h=r['source_after']['relevant_sources'][name]['actual_sha256']
    committed=subprocess.check_output(['git','--no-replace-objects','show',SHA+':'+name],cwd=ROOT)
    need(sha(committed)==h and sha((ROOT/name).read_bytes())==h,f'final_build_source:{name}')
validation_summary=read(VALIDATION/'summary.json')
need(validation_summary['expected_source_sha']==SHA
     and validation_summary['authority_native_runner_sha256']==artifact['sha256']
     and validation_summary['runner_bindings']==binding,'validation_summary_binding')
validation_files=['runner-bindings.json','source-after.json','authority-native-build.result.json',
    str(build_log_name),'summary.json']
validation_identity={name:{'bytes':(VALIDATION/name).stat().st_size,
    'sha256':sha((VALIDATION/name).read_bytes())} for name in validation_files}
qualification_markers=[line.decode('utf-8','replace') for line in build_log.splitlines()
    if b'UNQUALIFIED' in line]


capsule=(OUT/'owner/capsule.bin').read_bytes();body_raw=bytes.fromhex(prep['admission_pin']['body_hex'])
need(len(capsule)==862 and capsule[:6]==b'PGAC\0\0' and capsule[6:734]==body_raw and len(body_raw)==728,'capsule_raw_body')
body=decode_body(body_raw);freeze=config['freeze']
need(all(body['intent'][k]==v for k,v in freeze.items() if k!='now_ns'),'all_freeze_fields')
need(all(row['scope']==body['intent']['authorization_scope'] for row in config['requests']),'all_request_scopes')
materials=material_commitments(config['init'],config['requests'],now_ns=1)
need(all(body['intent'][k]==v for k,v in materials.items()),'independent_model_and_preinput_commitments')
registry=pon_hash(b'pon-grouped-owner-fixture-registry-v0',bytes.fromhex(materials['model_commitment']),bytes.fromhex(materials['request_precommitment']))
registry_digest=pon_hash(b'pon-grouped-owner-fixture-config-v0',(OUT/'config.json').read_bytes())
need(body['intent']['registry_id']==registry.hex() and body['intent']['registry_digest']==registry_digest.hex(),'registry_id_and_config_digest')
need(body['intent']['operation_id']==pon_hash(b'pon-grouped-owner-fixture-operation-v0',registry_digest).hex(),'operation_id')
need(body['intent']['transactions_commitment']==pon_hash(b'transactions-empty').hex() and body['intent']['registry_sequence']==1 and body['intent']['previous_registry_digest']=='00'*32,'remaining_canonical_intent_fields')
for role,index,offset in [(1,40,734),(2,41,798)]:
    key=public(index)
    need(key.hex()==prep['admission_pin']['requester_key' if role==1 else 'source_key'],'fixture_capsule_key_'+str(role))
    edverify(key,capsule[offset:offset+64],pon_hash(b'pon-grouped-fresh-capsule-signature-v0',bytes((role,)),body_raw))
    need(True,'independent_capsule_signature_'+str(role))
admission_policy=pon_hash(b'pon-grouped-fresh-external-policy-v0',public(40),public(41),(1).to_bytes(8,'big'),registry_digest,hashlib.sha256(capsule).digest(),body_raw)
need(admission_policy.hex()==prep['admission_pin']['policy_id'],'admission_policy_id')
reference_started=True
reference,reference_cost=independent_reference(config['init'],[dict(row,generation=config['init']['model_version'],representation=REPRESENTATION) for row in config['requests']])
candidates={item['nonce']:item for item in prep['candidates']};raw_registry=b''
for nonce,item in sorted(candidates.items()):
    candidate_raw=b'PGCE\0\0'+body_raw+nonce.to_bytes(8,'big')
    ch=pon_hash(b'pon-grouped-fresh-challenge-v0',candidate_raw);ident=pon_hash(b'pon-grouped-fresh-work-id-v0',candidate_raw)
    need(ch.hex()==item['challenge'] and ident.hex()==item['candidate'],'candidate_'+str(nonce))
    context=dict(chain=body['branch']['network'],parent=body['branch']['parent'],challenge=ch.hex(),batch_id=body['intent']['batch_id'])
    inputs=input_commitment(materials['model_commitment'],{'context':context,'requests':config['requests']})
    statement=statement_commitment(materials['model_commitment'],inputs,context,reference)
    need(item['claim']['product']==reference and item['claim']['model_commitment']==materials['model_commitment']
         and item['claim']['input_commitment']==inputs and item['claim']['statement_commitment']==item['statement']==statement,'full_reference_and_statement_'+str(nonce))
    raw_registry+=ident+nonce.to_bytes(8,'big')+ch+bytes.fromhex(statement)
target=bytes.fromhex(body['branch']['target'])
relation_id=pon_hash(b'pon-grouped-owner-material-v0',admission_policy,target,raw_registry)
policy=pon_hash(b'pon-grouped-verifier-authority-policy-v0',public(75),bytes.fromhex(config['epoch']),config['generation'].to_bytes(8,'big'),config['aggregate_limit'].to_bytes(8,'big'),config['per_candidate_limit'].to_bytes(8,'big'),relation_id,b''.join(sorted([public(73),public(74)])))
need(relation_id.hex()==prep['policy']['relation'] and policy.hex()==prep['policy']['policy'],'independent_owner_policy')

# Post-campaign audit calls are additional real queries, not covered by owner K.
endpoints={};audit_trace=[]
for nonce in [1,2,3,4,5,6]:
    c=candidates[nonce]
    state=hashlib.sha256(seal_frame(b'seed',profile,bytes.fromhex(c['challenge']),bytes.fromhex(c['statement']))).digest();seed_calls+=1
    for index in range(1,65):
        preimage=seal_frame(b'step',profile,bytes.fromhex(c['challenge']),index.to_bytes(2,'big'),state)
        state=hashlib.sha256(preimage).digest();step_calls+=1
        audit_trace.append({'nonce':nonce,'index':index,'input_hex':preimage.hex(),'output_hex':state.hex()})
    endpoints[c['candidate']]=state
producer=[json.loads(line,object_pairs_hook=unique) for line in (OUT/'producer-trace.ndjson').read_bytes().splitlines()]
need(len(producer)==192,'producer_trace_count')
need(producer==[row for row in audit_trace if row['nonce'] in [2,3,6]],'all_producer_step_preimages_and_outputs')

server_frames=Counter();client_frames=Counter();new_receipts=[];known_seed=known_steps=known_cell=0
raw_total_in=raw_total_out=0;response_signatures=receiver_signatures=0
for phase in range(1,5):
    directory=OUT/f'phase-{phase}';service=read(directory/'service-report.json');endpoint=read(directory/'endpoint.json')
    need(endpoint['policy']==policy.hex() and endpoint['authority']==public(75).hex() and endpoint['runner_sha256']==r['runner_sha256'],'endpoint_pin_'+str(phase))
    for index,event in enumerate(service['events'],1):
        request_raw=(directory/f'packets/{index:04}.request.json').read_bytes();response_raw=(directory/f'packets/{index:04}.response.json').read_bytes()
        wire=json.loads(request_raw,object_pairs_hook=unique);response=json.loads(response_raw,object_pairs_hook=unique)
        need(request_raw==canonical(wire)+b'\n' and response_raw==canonical(response)+b'\n','canonical_frames_'+str(phase)+'_'+str(index))
        fp=fingerprint(wire,policy);action={'reserve':1,'execute':2}[wire['command']['action']]
        edverify(bytes.fromhex(wire['receiver']),bytes.fromhex(wire['signature_hex']),pon_hash(b'pon-grouped-owner-receiver-signature-v0',bytes((action,)),fp));receiver_signatures+=1
        edverify(public(75),bytes.fromhex(response['signature_hex']),pon_hash(b'pon-grouped-owner-response-v0',policy,canonical(response['payload'])));response_signatures+=1
        need(response['authority']==public(75).hex() and response['payload']['request_sha256']==sha(request_raw) and response['payload']['policy']==policy.hex(),'response_binding_'+str(phase)+'_'+str(index))
        need(sha(request_raw)==event['request_sha256'] and sha(response_raw)==event['response_sha256'] and len(request_raw)==event['request_bytes'] and len(response_raw)==event['response_bytes_written'],'raw_frame_counters_'+str(phase)+'_'+str(index))
        server_frames[(sha(request_raw),sha(response_raw))]+=1;raw_total_in+=len(request_raw);raw_total_out+=len(response_raw)
        body=response['payload']['body']
        if body['ok'] and body['result']['state']=='complete':
            value=body['result'];receipt=value['receipt'];proof=bytes.fromhex(wire['command']['proof_hex'])
            need(receipt['request_fingerprint']==fp.hex() and receipt['receiver']==wire['receiver'] and receipt['request_id']==wire['command']['request_id'] and receipt['candidate']==wire['command']['candidate'],'receipt_full_request_binding_'+str(phase)+'_'+str(index))
            actual=endpoints[receipt['candidate']];valid=proof[102:]==actual
            need((receipt['outcome'] in ['verified_hit','verified_miss'])==valid,'independent_endpoint_relation_'+str(phase)+'_'+str(index))
            if valid:
                need(receipt['endpoint']==actual.hex() and (receipt['outcome']=='verified_hit')==(actual<=target),'independent_target_'+str(phase)+'_'+str(index))
            if value['cached']:
                need(value['new_step_queries']==value['new_seed_queries']==value['new_full_cell_calls']==0 and not value['new_candidate_completion'] and value['cached_response_does_not_revalidate_context'],'cached_cost_and_history_'+str(phase)+'_'+str(index))
            else:
                new_receipts.append(receipt);known_seed+=receipt['cost']['seed_queries'];known_steps+=receipt['cost']['step_queries'];known_cell+=receipt['cost']['full_cell_calls']
                need(receipt['cost']['full_cell_verified'] and receipt['cost']['step_queries']==64 and receipt['cost']['seed_queries']==1,'full_replay_counters_'+str(phase)+'_'+str(index))
    for receiver in [73,74]:
        client=read(OUT/f'phase-{phase}-receiver-{receiver}.report.json')
        for event in client['events']:
            raw=bytes.fromhex(event['request_raw_hex']);answer=bytes.fromhex(event['response_raw_hex'])
            need(event['authenticated_fixture_response'] and len(raw)==event['request_bytes_written'] and len(answer)==event['response_bytes'],'client_byte_counter_'+str(phase)+'_'+str(receiver)+'_'+str(event['planned_index']))
            client_frames[(sha(raw),sha(answer))]+=1
need(server_frames==client_frames and sum(server_frames.values())==30,'all_30_client_owner_frame_pairs')
need(known_steps==704 and known_seed==known_cell==11 and len(new_receipts)==11,'aggregate_callback_costs')
need(raw_total_in==sum(p['application_bytes_to_owner'] for p in r['phases'])==53460,'aggregate_input_frame_bytes')
need(raw_total_out==sum(p['application_bytes_from_owner'] for p in r['phases']),'aggregate_output_frame_bytes')

db=sqlite3.connect((OUT/'owner/authority.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True)
context=db.execute('SELECT schema,hex(policy),issued FROM context').fetchone()
need(context==('pon-grouped-verification-authority-v0',policy.hex().upper(),12),'sql_context')
rows=db.execute('SELECT sequence,receiver,request_id,candidate,fingerprint,state,receipt FROM submissions ORDER BY sequence').fetchall()
need(len(rows)==12 and [x[0] for x in rows]==list(range(1,13)),'sql_sequences')
state_counts=Counter(row[5] for row in rows);need(state_counts=={'complete':11,'reserved':1},'sql_dispositions')
by_sequence={v['sequence']:v for v in new_receipts}
for seq,receiver,request,candidate,fp,state,raw in rows:
    if raw:
        receipt=json.loads(raw,object_pairs_hook=unique)
        need(receipt==by_sequence[seq] and receipt['receiver']==receiver.hex() and receipt['request_id']==request.hex() and receipt['candidate']==candidate.hex() and receipt['request_fingerprint']==fp.hex(),'sql_receipt_'+str(seq))
closed=db.execute('SELECT candidate,sequence,endpoint FROM closed_candidates').fetchall();db.close()
need(len(closed)==3,'sql_three_closed_candidates')
for c,seq,e in closed:need(by_sequence[seq]['first_record'] and by_sequence[seq]['candidate']==c.hex() and e==endpoints[c.hex()],'sql_closed_binding_'+str(seq))
need(sum(v['first_record'] for v in new_receipts)==3 and all(v['chainwork_awarded']==0 for v in new_receipts),'no_duplicate_first_record_or_credit')
outcomes=Counter(v['outcome'] for v in new_receipts)

processes=r['all_processes'];need(len(processes)==13 and all(p['exit_code']==0 and p['status']=='exited' for p in processes),'all_13_processes_exited')
need(len({p['pid'] for p in processes})==13,'distinct_process_identities_in_campaign')
need(len([p for p in processes if p['label'].startswith('receiver-')])==8 and len([p for p in processes if p['label'].startswith('owner-')])==4,'receiver_owner_process_denominators')
usage={role:sum(p['user_seconds']+p['system_seconds'] for p in processes if (p['label'].startswith('owner-') if role=='owner' else p['label'].startswith('receiver-') if role=='receiver' else p['label']=='prepare')) for role in ['owner','receiver','prepare']}
native_cpu=sum(usage.values());all_children_cpu=r['all_children_user_seconds']+r['all_children_system_seconds']
need(native_cpu<=all_children_cpu+1e-6,'native_cpu_is_subset_of_all_children')
preps=[prep['prepare_cost']]+[read(OUT/f'phase-{p}/service-report.json')['startup_prepare_cost'] for p in range(1,5)]
need(all(p['prepared_model_instances']==1 and p['direct_business_observations']==16 and p['direct_business_macs']==16*16*6*257 and p['seal_step_queries']==0 and p['seal_seed_queries']==0 for p in preps),'five_complete_startup_preparations')
need(r['final_snapshot']['full_cell_verified_calls']==11 and r['final_snapshot']['verified_cell_macs_known']==11*37008 and r['final_snapshot']['incomplete_cell_macs_unknown_upper']==0,'cell_mac_intervals')

result={'schema':'pon-grouped-owner-independent-audit-portable-v2','status':'PASS','source_commit':SHA,'source_runner_sha256':r['runner_sha256'],
    'source_tree':tested_tree,'campaign':str(OUT),'validation_directory':str(VALIDATION),
    'audit_script_sha256':sha(pathlib.Path(__file__).read_bytes()),
    'validation_identity_files':validation_identity,
    'validation_status':validation_summary['status'],
    'validation_commands_planned':validation_summary['commands_planned'],
    'validation_commands_passed':validation_summary['commands_passed'],
    'authority_build_unqualified_markers':qualification_markers,
    'reproducible_build_attestation':False,
    'historical_fixture_challenges_previously_used':True,
    'hits_are_schedule_observations_not_probability_estimate':True,
    'all_historical_and_subsequent_assistance_requires_separate_accounting':True,
    'report_sha256':sha((OUT/'report.json').read_bytes()),'checks':checks,'checks_passed':len(checks),
    'independent_capsule_signatures':2,'independent_receiver_signatures':receiver_signatures,'independent_owner_response_signatures':response_signatures,
    'frames_received_bytes':raw_total_in,'frames_sent_bytes':raw_total_out,'frames_each_direction':30,
    'native_owner_steps':known_steps,'native_owner_seeds':known_seed,'native_full_cell_calls':known_cell,'producer_steps':192,'producer_seeds':3,
    'post_campaign_audit_chain_step_queries':step_calls,'post_campaign_audit_seed_queries':seed_calls,
    'post_campaign_audit_reference_macs':reference_cost.reference_macs,'post_campaign_audit_reference_additions':reference_cost.reference_additions,
    'post_campaign_audit_cost_scope':'Additional independent audit, outside original campaign K and timing. Include in an expanded assistance/accounting horizon; endpoints are not exported by this report.',
    'whole_before_audit_report_wall_ns':time.perf_counter_ns()-start,'audit_process_cpu_ns':time.process_time_ns()-cpu,
    'campaign_native_cpu_seconds_by_role':usage,'campaign_native_cpu_seconds_total':native_cpu,'campaign_all_children_cpu_seconds':all_children_cpu,
    'startup_direct_business_macs':sum(p['direct_business_macs'] for p in preps),'startup_merge_additions':sum(p['cached_model_merge_additions'] for p in preps),
    'verified_callback_macs':11*37008,'outcomes':dict(outcomes),'final_reserved':12,'final_complete':11,'final_reserved_abandoned':1,
    'all_keys_public_test_fixtures':True,'independent_operators':False,'global_budget_proved':False,'physical_durability_proved':False,'chainwork_awarded':0}
for name,identity in validation_identity.items():
    need((VALIDATION/name).stat().st_size==identity['bytes']
         and sha((VALIDATION/name).read_bytes())==identity['sha256'],f'validation_identity_stable:{name}')
result['checks_passed']=len(checks)
audit_children_after=resource.getrusage(resource.RUSAGE_CHILDREN)
result['audit_children_user_seconds']=audit_children_after.ru_utime-audit_children_before.ru_utime
result['audit_children_system_seconds']=audit_children_after.ru_stime-audit_children_before.ru_stime
result['audit_timing_scope']='Measured from after Python/module imports through final validation-file identity checks; parent CPU and git-helper child CPU are separate; final JSON encoding/write and process exit excluded.'
result['whole_before_audit_report_wall_ns']=time.perf_counter_ns()-start
result['audit_process_cpu_ns']=time.process_time_ns()-cpu
with DEST.open('x') as f:json.dump(result,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')
print(json.dumps({k:result[k] for k in ['status','checks_passed','independent_capsule_signatures','independent_receiver_signatures','independent_owner_response_signatures','post_campaign_audit_chain_step_queries','campaign_native_cpu_seconds_by_role','startup_direct_business_macs','outcomes']},indent=2))
