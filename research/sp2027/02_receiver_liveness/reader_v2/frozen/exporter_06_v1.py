#!/usr/bin/env python3
"""Normalize byte-pinned native archives without running a node or inventing clocks.

Original ZIPs are required on first import. The exported original-member capsule
retains complete reports and provenance, without executable binaries/databases.
Read-only imports never turn a failed original acceptance gate into a pass.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import math
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
READER = HERE.parent / '02_receiver_liveness' / 'replay_native_evidence.py'
READER_SHA = 'b62034432a144927fe570012aefc5c438bf364a31888047bac1bee1585310930'
M = '11e242dbaaae14a9d16282fe8deaf36827e98395'
M_TREE = '1f42f41923d7761c02fc68b478df5b019c7d83e8'
M_SHA = '96b801074e063222a807a75a012da57f3255f95f3cc0301b7eb012f8188aec78'
M_REPORTS = ['20b0610468fa9b781e69f80a1210442cbfc8536a99b28c567ed6ee2b0b0bc08f',
             '5d56f8557c165a8ed326c54f329767ad60d28b2c366ba17b1dff404042cace86',
             '4866a9ed85a261de4b7d4fa427b719e40009dd9b930fb62cfde8aaa22dc49327']
SOURCE_TREES = {
 'ac8501a85a770ba34f34e1bed507ca747e5c3f8d':'3f321d412ab7eb1f5c03f18ba21201e96a3db144',
 '81f00ca62d9ce53483d56d2f2ec12fb871a0b3ae':'ddd05172f0ff481ac2a02329ab03ea7eabc59473',
 M:M_TREE,
}
BINARY_SHA256 = {
 'm14_campaign':'3634acc71b9b77b8ef4aec487ecc487b5b5a1b60d11e949847d435d5ff74d027',
 'm14_protocol':'febf019484c1fbe34e2920451b5c2e3e16021e6d9583b52eab74f986beaf1b9e',
 'm14_fresh':'77f18cec6c8eb7ee5c399d61853772afb73a729d0cf976cc36b45e2fefc80147',
 'm14_f0':'e3291d85be75827ad6de58f9b9e023718bc9bfd6b95c34460c5c0073c4b6d7fb',
 'pr856_campaign':'e0eaf60b5a9b02b423863e68f897d4b7254f0b597ec7994b90c5234feee3caec',
 'm_campaign':'96ef1d21f60fdffa1658a917e58e4f8dff7c0dd25c695abf9d940da921aec9da',
}
ORIGINS = {
 'm14_campaign': (42693805359,13708896865), 'm14_protocol': (42693804931,13711685364),
 'm14_fresh': (42693804271,13708332726), 'm14_f0': (42693805049,13709705081),
 'pr856_campaign': (42773664165,13743836733), 'm_campaign': (42960214803,13833660378),
}

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def integer(x):
    return type(x) is int and x >= 0

def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('NONFINITE_JSON:' + value)
    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), 'NONFINITE_JSON:' + value)
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite_float)

def validate_retained_identity(key, identity, read_raw, commit):
    """Reconcile receipt fields with retained native metadata, without binary bytes.

    Binary hashes here are checks of the original recorded metadata against the
    pinned first-import hash. This is not a new executable or ZIP rehash.
    """
    require(commit in SOURCE_TREES and key in BINARY_SHA256, 'CAPSULE_SOURCE_UNKNOWN_PROFILE')
    expected_tree, expected_binary = SOURCE_TREES[commit], BINARY_SHA256[key]

    def original_json(member):
        raw = read_raw(member)
        record = identity.get('read_members', {}).get(member)
        require(isinstance(record, dict) and record.get('bytes') == len(raw)
                and record.get('sha256') == sha(raw), 'CAPSULE_ORIGINAL_MEMBER_BINDING:' + member)
        return strict_json(raw)

    if key in {'m14_protocol', 'm14_fresh'}:
        prefix = 'from-zero-native' if key == 'm14_protocol' else 'fresh-service'
        native = original_json(prefix + '/manifest.json')
        before = native['source_before']['tracked_source_identity']
        after = native['source_after']['tracked_source_identity']
        require(native.get('binary_sha256_before') == native.get('binary_sha256_after')
                == identity.get('binary_sha256') == expected_binary, 'CAPSULE_BINARY_MANIFEST_BINDING')
        binary_member = prefix + '/public_v3_from_zero'
        native_bytes = None
    else:
        before = original_json('source-before.json')
        after = original_json('source-after.json')
        native = original_json('execution/results.json' if key == 'm14_f0' else 'results.json')
        binary = native.get('binary')
        require(isinstance(binary, dict) and binary == identity.get('binary'), 'CAPSULE_BINARY_METADATA_BINDING')
        if key == 'm14_f0':
            require(binary.get('sha256') == expected_binary, 'CAPSULE_BINARY_DIGEST')
            matches = [name for name in identity['read_members'] if name.endswith('public_v3_multiprocess.bin')]
            require(len(matches) == 1, 'CAPSULE_BINARY_MEMBER_SET')
            binary_member = matches[0]
        else:
            require(binary.get('sha256_before') == binary.get('sha256_after') == expected_binary, 'CAPSULE_BINARY_DIGEST')
            binary_member = binary.get('retained')
        native_bytes = binary.get('bytes')
        require(integer(native_bytes) and native_bytes > 0, 'CAPSULE_BINARY_SIZE')
    for label, source in [('before', before), ('after', after)]:
        require(isinstance(source, dict) and source == identity.get('source_' + label), 'CAPSULE_SOURCE_RECEIPT_BINDING:' + label)
        require(source.get('schema') == 'trnm-ci-source-v1'
                and source.get('tested_commit') == source.get('candidate') == commit
                and source.get('tested_tree') == expected_tree, 'CAPSULE_SOURCE_PIN:' + label)
        require(source.get('tracked_worktree_verified') is True and source.get('kind') == 'head'
                and source.get('prospective_merge') is None, 'CAPSULE_SOURCE_EXECUTION_SCOPE:' + label)
    binary_record = identity.get('read_members', {}).get(binary_member)
    require(isinstance(binary_record, dict) and binary_record.get('sha256') == expected_binary,
            'CAPSULE_BINARY_ORIGINAL_RECEIPT')
    if native_bytes is not None:
        require(binary_record.get('bytes') == native_bytes, 'CAPSULE_BINARY_ORIGINAL_SIZE')

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())

def load_reader():
    require(sha(READER.read_bytes()) == READER_SHA, 'UPSTREAM_READER_CHANGED')
    spec = importlib.util.spec_from_file_location('sp27_pinned_native_reader', READER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ARCHIVES['m_campaign'] = ('chain-throughput-m-campaign.zip',81779634,M_SHA,M)
    return module

class Export:
    def __init__(self):
        self.runs, self.schedule, self.events, self.diagnostics = [], [], [], []
        self.members, self.identities = {}, []

    def retain(self, archive, member, raw):
        name = archive + '/' + member
        old = self.members.get(name)
        require(old is None or old == raw, 'CONFLICTING_RETAINED_MEMBER')
        self.members[name] = raw

    def event(self, run, kind, oid=None, at=None, actor=None, **extra):
        event = {'event_id':run['run_id']+'/event-'+str(len(self.events)),
                 'run_id':run['run_id'],'operation_id':oid,'type':kind,'at_ns':at,
                 'clock_id':run['clock_id'],'actor_id':actor or run['observer_id'],
                 'attempt_id':oid+'/attempt-0' if oid else None}
        event.update(extra)
        self.events.append(event)

    def run(self, a, phase_id, row, phase, report, identity, member):
        source = identity['source_before']
        binary = identity.get('binary_sha256')
        if binary is None:
            binary = identity['binary'].get('sha256_before', identity['binary'].get('sha256'))
        # A digest of an observed projection is not a complete config freeze.
        observed_config = {k:report.get(k) for k in ['settings_profile','state_backend','public_resource_policy','policy_id']}
        run = {'run_id':phase_id,'chain_instance_id':phase_id+'/fresh-ledger',
               'profile_id':row['fixture'],'clock_id':phase_id+'/traffic-epoch',
               'observer_id':phase_id+'/independent-native-client',
               'window_start_ns':0,'window_end_ns':row['window_ns'],
               'confirmation_policy':{'policy_id':'installed-depth-and-required-work','min_depth':6,
                                      'required_work_delta':'0c','semantics':'first_observed',
                                      'window_end_rule':'exclusive','require_native_window_gate':True},
               'identity':{'source_commit':source['tested_commit'],'source_tree':source['tested_tree'],
                           'binary_sha256':binary,'config_sha256':None},
               'event_coverage_complete':True,'resource_inventory_complete':False,
               'recovery':None,
               'metadata':{'archive_key':a.key,'mode':phase['mode'],'report_member':member,
                           'report_sha256':sha(a.z.read(member)),'zip_sha256':a.identity['zip_sha256'],
                           'observed_config_view':observed_config,'observed_config_view_sha256':sha(canonical(observed_config)),
                           'config_freeze_complete':False,'plan_provenance':'frozen fixture source; retrospective import',
                           'same_host_only':True,'independent_operational_domains':False,
                           'prospective_registration':False,'original_gate_unchanged':True,
                           'event_coverage_scope':'all fixture planned round starts and recorded native observations, not all physical activity',
                           'confirmation_attestation_scope':'positive native independent endpoint plus source path; cryptography not reexecuted by Python',
                           'clock_resolution_ns':None,'clock_error_bound_ns':None,
                           'saturation_capacity_measured':False,'new_useful_computation_evidence':None}}
        self.runs.append(run)
        return run

    def operation(self, run, index, tx, block, scheduled, deadline, pointer):
        oid=run['run_id']+'/operation-'+str(index)
        self.schedule.append({'operation_id':oid,'run_id':run['run_id'],'scheduled_ns':scheduled,
                              'deadline_ns':deadline,'transaction_ids':[tx],'expected_block_id':block,
                              'content_id':'signed-transaction-digest:'+tx,
                              'useful_compute_id':None,'useful_compute_evidence':None,
                              'plan_provenance':pointer})
        return oid

    def confirmation(self, run, oid, at, obs, a, member, pointer, native_gate):
        require(obs['policy']=='installed-depth-and-required-work','POLICY')
        require(obs['confirmed'] is True and obs['finalized'] is False and obs['execution_authority'] is False,'OBSERVATION_NOT_FINALITY')
        require(obs.get('reorged') is False,'REORGED_OBSERVATION')
        require(integer(at) and type(obs['depth']) is int and obs['depth']==6,'CONFIRMATION_CLOCK_DEPTH')
        require(type(native_gate) is bool,'NATIVE_WINDOW_GATE_TYPE')
        require(not native_gate or at < run['window_end_ns'],'NATIVE_WINDOW_GATE_CLOCK_CONTRADICTION')
        require(int(obs['required_work_delta'],16)==12 and int(obs['work_delta'],16)>=12,'WORK_POLICY')
        self.event(run,'confirmation',oid,at,transaction_id=obs['transaction'],block_id=obs['included_block'],
                   policy_id=obs['policy'],depth=obs['depth'],work_delta=obs['work_delta'],
                   required_work_delta=obs['required_work_delta'],execution_authority=False,native_window_gate=native_gate,
                   flags={k:True for k in ['full_verification','admission','host','history','activation']},
                   flags_provenance='native successful confirmation path attestation; not independent Python verification',
                   provenance={'artifact_sha256':a.identity['zip_sha256'],'member':member,'pointer':pointer})

    def resources(self, run, p):
        # Keep inclusive stage counters but never add them to their parents.
        fields=[('whole_parent_phase_cpu_ns','phase-parent','whole_lifecycle',False),
                ('receiver_and_verifier_setup_cpu_ns','setup-nested','setup',True),
                ('reader_cpu_ns','client-reader','whole_lifecycle',False),
                ('independent_replay_and_confirmation_cpu_ns','independent-replay-caller-thread','whole_lifecycle',False),
                ('attacker_workers_cpu_ns','attacker-worker-total','whole_lifecycle',False)]
        for field,owner,scope,inclusive in fields:
            value=p.get(field)
            if integer(value):
                self.event(run,'resource',metric='cpu_ns',value=value,owner_id=owner,scope=scope,
                           inclusive=inclusive,coverage='partial',started_ns=None,ended_ns=None,
                           native_field=field,whole_span_only=True)
        # Full lifecycle and exact in-window CPU remain unknown without all owners.

    def campaign_phase(self, lib, a, member, report, row, identity):
        pi=int(row['json_pointer'].split('/')[-1]); p=report['phases'][pi]
        prep=report['preparation']
        business=prep.get('business')
        if business is None:
            business=[lib.decode_packet_fields(x) for x in prep['business_packets']]
        require([i for i,b in enumerate(business) if b['transactions']]==[0,7,14],'BUSINESS_SET')
        run=self.run(a,row['phase_id'],row,p,report,identity,member)
        require(all(type(r.get('round')) is int and 0 <= r['round'] < 3 for r in p['confirmations']),
                'ROUND_INDEX_TYPE_OR_RANGE')
        by_round={r['round']:r for r in p['confirmations']}
        require(len(by_round)==len(p['confirmations']) and set(by_round)<=set(range(3)),'ROUND_DUPLICATE_OR_UNPLANNED')
        operations={}
        for i in range(3):
            rawtx=bytes.fromhex(business[7*i]['transactions'][0]); tx=lib.wire_hash(b'tx-id',rawtx)
            scheduled=(1+4*i)*1_000_000_000
            deadline=scheduled+4_000_000_000 if a.key=='m14_f0' else run['window_end_ns']
            oid=self.operation(run,i,tx,business[7*i]['id'],scheduled,deadline,
                               'public_v3_multiprocess.rs phase(): 1s + round*4s; signed packet indices 0,7,14')
            operations[i]=oid
            r=by_round.get(i)
            if r is None:
                self.event(run,'not_started',oid,run['window_end_ns'],reason='absent from complete original round roster')
                continue
            require(integer(r['started_ns']) and integer(r['ended_ns']) and scheduled<=r['started_ns']<=r['ended_ns'],'ROUND_CLOCK_ORDER')
            require(r['transaction']==tx and r['included_block']==business[7*i]['id'],'ROUND_IDENTITY')
            self.event(run,'request_start',oid,r['started_ns'])
            self.event(run,'attempt_end',oid,r['ended_ns'],recorded_confirmed=r['confirmed_inside_pressure_window'])
            obs=r.get('observation')
            if obs and obs.get('confirmed') is True:
                require(obs['transaction']==tx and obs['included_block']==business[7*i]['id'],'OBSERVATION_IDENTITY')
                self.confirmation(run,oid,r['ended_ns'],obs,a,member,row['json_pointer']+'/confirmations/'+str(list(by_round).index(i))+'/observation',r['confirmed_inside_pressure_window'])
            else:
                # A deadline/nonconfirmation is not proof of irreversible business failure.
                self.event(run,'stage',oid,r['ended_ns'],stage='confirmation_attempt',outcome='unconfirmed')
        for sub in p['submissions']:
            require(type(sub['packet_index']) is int and 0<=sub['packet_index']<21,'PACKET_INDEX')
            require(integer(sub['started_ns']) and integer(sub['ended_ns']) and sub['started_ns']<=sub['ended_ns'],'SUBMIT_CLOCK')
            if sub.get('status')=='ok':
                self.event(run,'ack',operations[sub['packet_index']//7],sub['ended_ns'],packet_index=sub['packet_index'])
        self.resources(run,p)
        self.event(run,'observer_end',at=run['window_end_ns'],reason='original phase endpoint')
        self.diagnostics.append({'run_id':run['run_id'],'original_gate':row['original_finite_phase_criteria_met'],
                                 'planned':3,'confirmed':row['confirmed_in_window'],'unstarted':row['rounds_unstarted'],
                                 'ack_packets':row['successful_ack_packets'],'seed_transfers_excluded':1024,
                                 'history_import':row['history_import'],'history_import_errors':row['history_import_errors'],
                                 'stage_audit':row['stage_audit'],'receiver':row['receiver'],
                                 'parent_cpu_ns':p.get('whole_parent_phase_cpu_ns'),'parent_wall_ns':p.get('whole_parent_phase_wall_ns')})

    def pair_phase(self, lib, a, member, report, row, identity):
        pi=int(row['json_pointer'].split('/')[-1]); p=report['phases'][pi]
        run=self.run(a,row['phase_id'],row,p,report,identity,member)
        oid=self.operation(run,0,row['prepared_transaction_id'],row['prepared_packet_ids'][0],None,
                           run['window_end_ns'],'one signed transaction plus six depth blocks; planned time absent in archive')
        start=p['business_started_ns']; end=p['confirmation_ended_ns']; latency=p['client_confirmation_latency_ns']
        require(integer(start),'PAIR_START')
        require((end is None and latency is None) or (integer(end) and end>=start and latency==end-start),'PAIR_LATENCY_ORDER')
        self.event(run,'request_start',oid,start)
        obs=p.get('independent_client_confirmation')
        if obs and obs.get('confirmed') is True:
            self.confirmation(run,oid,end,obs,a,member,row['json_pointer']+'/independent_client_confirmation',p['client_confirmed_before_original_window_end'])
        for sub in p['honest_submissions']:
            if sub.get('status')=='ok':
                self.event(run,'ack',oid,sub['ended_ns'])
        for head in p['honest_heads']:
            if head.get('status')=='ok':
                self.event(run,'head',oid,head['ended_ns'])
        self.resources(run,p)
        self.event(run,'observer_end',at=run['window_end_ns'])
        self.diagnostics.append({'run_id':run['run_id'],'original_gate':row['original_finite_business_target_met'],
                                 'planned':1,'confirmed':row['confirmed_in_window'],'unstarted':0,
                                 'ack_packets':sum(x.get('status')=='ok' and x['ended_ns']<=run['window_end_ns'] for x in p['honest_submissions']),
                                 'head_successes':row['honest_head_successes_in_window'],
                                 'fixed_window_attack_overlaps':row['attack_calls_overlapping_fixed_business_window'],
                                 'confirmation_conditioned_overlap':row['reported_confirmation_conditioned_overlap_count'],
                                 'history_import':row['history_import'],'stage_audit':row['stage_audit'],
                                 'clock_mapping':row['clock_mapping'],'recovery_time_ns':None})

    def write(self,out,reuse=None,replayed=False):
        out.mkdir(parents=True,exist_ok=False)
        contract={'schema':'sp27-confirmed-goodput-contract-v1','evidence_scope':'archival_reanalysis',
                  'experiment_id':'sp27-06-native-archives-20261111','runs':self.runs,
                  'joint_freeze_status':'proposed_v1_validated_against_02_archives; no Agent02 acknowledgement fabricated',
                  'counting':'business trial operations scoped by independently reset ledger; content=exact signed transaction digest; useful computation unmeasured',
                  'shared_with_sp27_02':True,'new_native_experiments':0}
        dump(out/'contract.json',contract)
        for name,rows in [('schedule.jsonl',self.schedule),('events.jsonl',self.events)]:
            (out/name).write_bytes(b''.join(canonical(x) for x in rows))
        dump(out/'diagnostics.json',self.diagnostics)
        dump(out/'archive_verification.json',{'archives':self.identities,'reader_sha256':READER_SHA,
             'exporter_sha256':sha(Path(__file__).read_bytes()),'new_native_experiments':0,
             'all_zip_and_retained_binary_bytes_rehashed':not replayed,
             'raw_report_capsule_replay':replayed,
             'original_import_verified_zip_and_retained_binaries':True,
             'old_replay_output_sha256':'3390ac2177007bcc251974683845429375401029fe67ab74dc5e2c909992ebb2',
             'evidence_delivery_commit_for_M':'04c848f3b593ba0c493b4ca3beebc0d91d52f2c7'})
        manifest={name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(self.members.items())}
        dump(out/'original_members.json',manifest)
        # Deterministic complete raw JSON/source-member capsule. No unsafe extraction.
        if reuse is not None:
            old_members=strict_json((reuse/'original_members.json').read_bytes())
            old_inputs=strict_json((reuse/'input_manifest.json').read_bytes())
            require(old_members==manifest,'CAPSULE_MEMBER_MANIFEST_CHANGED')
            capsule=reuse/'native_originals.tar.xz'
            require(sha(capsule.read_bytes())==old_inputs['files'][capsule.name]['sha256'],'CAPSULE_DIGEST')
            shutil.copyfile(capsule,out/capsule.name)
        else:
            with tarfile.open(out/'native_originals.tar.xz','w:xz',preset=6) as archive:
                for name,raw in sorted(self.members.items()):
                    info=tarfile.TarInfo(name); info.size=len(raw); info.mtime=0; info.mode=0o644
                    archive.addfile(info,io.BytesIO(raw))
        dump(out/'input_manifest.json',{'files':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
             for p in sorted(out.iterdir()) if p.is_file()},'created_by':'export_archives.py; archive read only'})
        print(json.dumps({'phase_runs':len(self.runs),'planned_operations':len(self.schedule),'events':len(self.events),
                          'native_experiments':0,'out':str(out),'capsule_bytes':(out/'native_originals.tar.xz').stat().st_size}))

def from_capsule(lib,directory):
    """Re-derive events from complete retained reports, not precomputed summaries.

This verifies all retained raw member bytes. Original binary/ZIP verification is
attributed to the first import receipt; those bytes are deliberately not present.
"""
    imported=strict_json((directory/'archive_verification.json').read_bytes())
    manifest=strict_json((directory/'original_members.json').read_bytes())
    inputs=strict_json((directory/'input_manifest.json').read_bytes())
    for name,record in inputs['files'].items():
        require(type(name) is str and Path(name).name == name and name not in {'.', '..'}, 'CAPSULE_INPUT_PATH')
        path=directory/name
        require(path.is_file() and path.stat().st_size==record['bytes'] and sha(path.read_bytes())==record['sha256'],'CAPSULE_INPUT:'+name)
    export=Export()
    with tarfile.open(directory/'native_originals.tar.xz','r:xz') as archive:
        entries=archive.getmembers()
        require(len(entries)==len(manifest) and len({x.name for x in entries})==len(entries),'CAPSULE_MEMBER_SET')
        for entry in entries:
            require(not PurePosixPath(entry.name).is_absolute() and '..' not in PurePosixPath(entry.name).parts,
                    'CAPSULE_UNSAFE_MEMBER')
            require(entry.isfile() and entry.name in manifest,'CAPSULE_MEMBER_TYPE_OR_NAME')
            require(entry.size==manifest[entry.name]['bytes'],'CAPSULE_MEMBER_SIZE')
            raw=archive.extractfile(entry).read()
            require(sha(raw)==manifest[entry.name]['sha256'],'CAPSULE_MEMBER_DIGEST')
            export.members[entry.name]=raw

    class RawMembers:
        def __init__(self,key): self.key=key
        def read(self,name): return export.members[self.key+'/'+name]

    class CapsuleArchive:
        def __init__(self,key,identity):
            self.key=key; self.identity=identity; self.commit=identity['commit']; self.reads={}
            self.z=RawMembers(key)
        def read(self,name):
            raw=self.z.read(name); self.reads[name]={'bytes':len(raw),'sha256':sha(raw)}
            return strict_json(raw)

    identities={x['archive'].removesuffix('.zip'):x for x in imported['archives']}
    require(len(identities)==len(imported['archives'])==len(lib.ARCHIVES),'CAPSULE_IDENTITY_SET')
    for key,(filename,size,digest,commit) in lib.ARCHIVES.items():
        identity=identities[filename.removesuffix('.zip')]
        require(identity['zip_bytes']==size and identity['zip_sha256']==digest and identity['commit']==commit,'CAPSULE_ORIGIN')
        a=CapsuleArchive(key,identity)
        for retained_name,raw in export.members.items():
            prefix=key+'/'
            if retained_name.startswith(prefix):
                original=identity.get('read_members',{}).get(retained_name[len(prefix):])
                require(isinstance(original,dict) and original.get('bytes')==len(raw)
                        and original.get('sha256')==sha(raw),'CAPSULE_ORIGINAL_MEMBER_BINDING:'+retained_name)
        validate_retained_identity(key,identity,a.z.read,commit)
        export.identities.append(identity)
        if key.endswith('campaign'):
            reports=[(i,f'run-{i}-raw/report.json') for i in range(1,4)]
        elif key=='m14_f0': reports=[(1,'execution/raw/report.json')]
        elif key=='m14_fresh': reports=[('original','fresh-service/original/report.json'),('fresh','fresh-service/fresh/report.json')]
        else: reports=[('confirmation','from-zero-native/confirmation/report.json')]
        for label,member in reports:
            report=a.read(member)
            require(a.reads[member]['sha256']==identity['read_members'][member]['sha256'],'ORIGINAL_REPORT_BINDING')
            if key.endswith('campaign') or key=='m14_f0':
                prep=report['preparation']
                if key=='m14_f0':
                    prep={'business':[lib.decode_packet_fields(x) for x in prep['business_packets']],
                          'actual_signed_seed_transfers':sum(len(lib.decode_packet_fields(x)['transactions']) for x in prep['seed_packets'])}
                for i,phase in enumerate(report['phases']):
                    row=lib.native_phase(a,member,phase,prep,label,i,'fixed-root-f0' if key=='m14_f0' else 'original-3x3-native')
                    export.campaign_phase(lib,a,member,report,row,identity)
            else:
                decoded=[lib.decode_packet_fields(x) for x in report['signed_honest_packets']]
                require([len(x['transactions']) for x in decoded]==[1,0,0,0,0,0,0],'PAIR_SIGNED_SET')
                tx=lib.wire_hash(b'tx-id',bytes.fromhex(decoded[0]['transactions'][0]))
                for i,phase in enumerate(report['phases']):
                    obs=phase.get('independent_client_confirmation')
                    if obs: require(obs['transaction']==tx and obs['included_block']==decoded[0]['id'],'PAIR_BINDING')
                    row=lib.pair_phase(a,member,phase,i,label)
                    row.update(prepared_transaction_id=tx,prepared_packet_ids=[x['id'] for x in decoded])
                    row['fixture']='fresh-challenge-four-second-pair' if label=='fresh' else 'original-four-second-pair'
                    export.pair_phase(lib,a,member,report,row,identity)
    require(len(export.runs)==35 and len(export.schedule)==93,'CAPSULE_CORPUS')
    return export

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--archive-dir',type=Path)
    source.add_argument('--capsule-dir',type=Path)
    parser.add_argument('--reuse-capsule-from',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); lib=load_reader(); export=Export()
    if args.capsule_dir:
        from_capsule(lib,args.capsule_dir).write(args.output,reuse=args.capsule_dir,replayed=True)
        return
    for key,(name,*_) in lib.ARCHIVES.items():
        a=lib.Archive(key,args.archive_dir/name)
        if key.endswith('campaign'): rows=lib.campaign(a)
        elif key=='m14_f0': rows=lib.f0(a)
        else: rows=lib.pairs(a,key=='m14_fresh')
        identity=a.identity
        if key=='m_campaign':
            require(identity['source_before']['tested_tree']==M_TREE,'M_TREE')
            for i,digest in enumerate(M_REPORTS,1): require(a.reads[f'run-{i}-raw/report.json']['sha256']==digest,'M_REPORT')
        reports={}
        for row in rows:
            member=row['report_member']
            if member not in reports:
                raw=a.z.read(member); export.retain(key,member,raw); reports[member]=strict_json(raw)
            if 'prepared_transaction_id' in row: export.pair_phase(lib,a,member,reports[member],row,identity)
            else: export.campaign_phase(lib,a,member,reports[member],row,identity)
        # Include native source/build/environment records that exist; missing is explicit.
        optional=['source-before.json','source-after.json','results.json','hardware.json','cargo-version.txt',
                  'rustc-version.txt','build.step.json','binary-before.json','resource-before-build.json',
                  'resource-after-native.json','execution/results.json','execution/predeclared.json',
                  'fresh-service/manifest.json','from-zero-native/manifest.json',
                  'from-zero-native/format-copy-source/tests/public_v3_from_zero.rs']
        for name in optional:
            if name in a.z.namelist(): export.retain(key,name,a.raw(name))
        finished=a.finish(); finished['actions_run_id'],finished['artifact_id']=ORIGINS[key]
        export.identities.append(finished)
    require(len(export.runs)==35 and len(export.schedule)==93,'EXPECTED_CORPUS_INVENTORY')
    export.write(args.output,reuse=args.reuse_capsule_from)

if __name__=='__main__': main()
