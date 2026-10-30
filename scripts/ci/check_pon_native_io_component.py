#!/usr/bin/env python3
"""Strict readback of the original finite public three-FD component run.

This reader requires the retained original preparation, claim and execution
objects. It is not host attestation, archive inode authentication, a full writer
audit, a 4097-identity result or model/service qualification.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import run_pon_native_io_component as component
import check_pon_identity_churn as original
from read_original_native_campaign import Bundle, strict_json
from run_pon_identity_churn import held_directory, checked_member, identity, held_file_names
from contract_wire import H, tx_decode
from strict_signature import verify as verify_signature

require = component.require
MIB = 1024**2
SCHEMA = 'pon-native-io-three-fd-component-readback-v1'
MODE = 'fresh-identities'
PHASE = 'raw/' + MODE + '/'
ROLES = {0: 'honest-miner', 5: MODE+'/receiver', 6: MODE+'/independent-client'}


def same(actual, expected):
    component.typed(actual, expected)


def positive(value, minimum=0, maximum=2**127-1):
    require(type(value) is int and minimum <= value <= maximum, 'COMPONENT_TYPED_INTEGER_REQUIRED')
    return value


def flags(value):
    original.flags(value)
    if isinstance(value, dict):
        for key, item in value.items():
            if key in component.FULL_FLAGS: require(item is False, 'COMPONENT_FULL_FLAG_FORBIDDEN')
            flags(item)
    elif isinstance(value, list):
        for item in value: flags(item)


def component_process_limits(value, role, group, pid=None):
    # Finite receipts report the still-unimplemented full ledger honestly.
    # Preserve every original role/schema/PID/cgroup/AS/FSIZE assertion without
    # mutating the receipt or granting the original full-reader qualification.
    caps = original.profile('v2')['evidence_caps']
    require(role in ('actor', 'campaign-parent') and type(value) is dict
            and value['schema'] == caps['schema'] and value['role'] == role
            and value['original_cgroup_required'] is True and value['full_ledger_implemented'] is False,
            'incomplete native process limit owner')
    before, after = value['before'], value['after']
    original.v2_identity_types('process_observation', before)
    original.v2_identity_types('process_observation', after)
    if pid is not None:
        original.integer(pid, 1)
    require(before['pid'] == after['pid'] and (pid is None or after['pid'] == pid)
            and before['cgroup'] == after['cgroup'] == group, 'limit receipt process/cgroup changed')
    original.integer(after['pid'], 1)
    expected = dict(address_space=caps['actor_vm_bytes'] if role == 'actor' else caps['parent_vm_bytes'],
                    file_size=caps['actor_file_bytes'] if role == 'actor' else caps['parent_file_bytes'])
    for key, limit in expected.items():
        require(type(before[key]['soft_bytes']) is int and type(before[key]['hard_bytes']) is int
                and before[key]['soft_bytes'] >= limit and before[key]['hard_bytes'] >= limit
                and type(after[key]['soft_bytes']) is int and type(after[key]['hard_bytes']) is int
                and after[key]['soft_bytes'] == after[key]['hard_bytes'] == limit,
                'native address-space/file hard cap absent or changed')
    return after['pid']


def child_terminal(value, code):
    require(value['schema'] == 'pon-native-io-component-child-owner-v1'
        and value['spawn_count'] == 1 and type(value['spawn_count']) is int
        and value['reaped'] is True and value['failure'] is None
        and value['original_identity_alive_after_wait'] is False,
        'COMPONENT_ACTUAL_PARENT_TERMINAL_REQUIRED')
    positive(value['pid'], 1)
    positive(value['python_pid'], 1)
    positive(value['birth_ticks'], 1)
    same(value['observed_ppid'], value['python_pid'])
    same(value['wait_returncode'], code)
    return value['pid']


def first_dispatch(bundle, dispatch, caller, native_pid, binary):
    require(dispatch['schema'] == component.DISPATCH and dispatch['domain'] == component.DOMAIN
        and dispatch['component_only'] is True, 'COMPONENT_FIRST_DISPATCH_DOMAIN')
    descriptors = [positive(dispatch[key], 3, 2**31-1)
        for key in ('executable_fd', 'execution_directory_fd', 'cwd_directory_fd')]
    require(len(set(descriptors)) == 3, 'COMPONENT_DISTINCT_THREE_FD_REQUIRED')
    same(dispatch['inherited_fds'], sorted(descriptors))
    require(dispatch['actual_executable'] == '/proc/self/fd/'+str(descriptors[0])
        and dispatch['actual_cwd'] == '/proc/self/fd/'+str(descriptors[2])
        and dispatch['actual_raw_root'] == '/proc/self/fd/'+str(descriptors[1])+'/raw',
        'COMPONENT_ACTUAL_FD_PATHS_REQUIRED')
    original.caller_record(caller)
    same(caller['parent_pid'], native_pid)
    actual_executable = dict(identity=dispatch['executable_identity'],
        bytes=dispatch['executable_bytes'], sha256=dispatch['executable_sha256'])
    original.executable_pin(actual_executable)
    require(actual_executable['bytes'] == binary['bytes']
        and actual_executable['sha256'] == binary['sha256'], 'COMPONENT_CALLER_WRONG_BINARY')
    same(dispatch['execution_identity'], identity(os.fstat(bundle.fd)))
    original.live_original_identity(bundle, 'frozen/'+component.TARGET+'.bin',
                                    actual_executable['identity'], False)
    kinds = {'executable': (descriptors[0], actual_executable['identity']),
             'output': (descriptors[1], dispatch['execution_identity']),
             'source-cwd': (descriptors[2], dispatch['cwd_identity'])}
    require(len(caller['python_inputs']) == 3, 'COMPONENT_NATIVE_THREE_INPUT_CENSUS')
    seen = set()
    for row in caller['python_inputs']:
        require(row['kind'] in kinds and row['kind'] not in seen and row['before_cloexec'] is False,
                'COMPONENT_NATIVE_INPUT_CLASS_OR_QUARANTINE')
        seen.add(row['kind'])
        fd, object_id = kinds[row['kind']]
        same(row['fd'], fd)
        same(row['identity'], object_id)
    same(identity(os.stat(ROOT, follow_symlinks=False)), dispatch['cwd_identity'])
    return actual_executable


def seed_facts(value):
    require(value['schema'] == component.NATIVE_SCHEMA
        and len(value['seed_packets']) == 4 and len(value['business_packets']) == 21,
        'COMPONENT_ORIGINAL_PREPARATION_DENOMINATOR')
    positive(value['cpu_ns'], 1)
    positive(value['wall_ns'], 1)
    require(value['node_search_attempt_counts'] is None, 'COMPONENT_UNEXPOSED_SEARCH_COUNT')
    facts = [original.packet_facts(wire) for wire in value['seed_packets']+value['business_packets']]
    nonce = 0
    for index, fact in enumerate(facts):
        header = fact['header']
        require(header['height'] == index+1
            and (index == 0 or header['parent'].hex() == facts[index-1]['identity'])
            and header['network'] == facts[0]['header']['network']
            and header['parameters'] == facts[0]['header']['parameters'], 'COMPONENT_SEED_LINKAGE')
        same(len(fact['transactions']), 256 if index < 4 else 1 if (index-4) % 7 == 0 else 0)
        for raw in fact['transactions']:
            tx = tx_decode(raw)
            nonce += 1
            require(tx['nonce'] == nonce and tx['tag'] == 1 and tx['network'] == header['network'],
                    'COMPONENT_SIGNED_TRANSACTION_LINEAGE')
            verify_signature(tx['sender'], tx['signature'], H('tx-sign', tx['unsigned']))
    same(nonce, 1027)
    return facts


def root_terminal(bundle, role, native_pid, layout):
    index = positive(role['index'], 0, 6)
    require(index in ROLES and role['role'] == ROLES[index], 'COMPONENT_ACTUAL_USED_NODE_ROLE')
    row = role['receipt']
    require(row['schema'] == 'pn1-owned-sqlite-real-inode-v1'
        and row['owner_pid'] == native_pid and row['logical_bytes_limit'] == 48*MIB
        and row['retained_object_limit'] == 3 and row['failed'] is False
        and row['first_failure'] is row['first_failure_sqlite_code'] is None
        and row['secondary_failures'] == [] and row['secondary_failures_complete'] is True
        and row['lifecycle_complete'] is True and row['quarantine_entries_complete'] is True
        and row['quarantined_actual_states'] == row['denied_operations'] == 0
        and row['quarantined_sqlite_codes'] == [] and row['allocated_blocks_hard_cap_implemented'] is False,
        'COMPONENT_UNHEALTHY_OR_INCOMPLETE_ROOT')
    original.live_original_identity(bundle, 'raw/'+ROLES[index],
        dict(device=row['root_device'], inode=row['root_inode']), True)
    declared = layout['roles'][index]
    same(declared['index'], index)
    same(declared['root_dev_ino'], [row['root_device'], row['root_inode']])
    same(declared['registered_vfs'], role['registered_vfs'])
    require(len(row['objects']) <= positive(row['retained_objects_peak'], 0, 3)
        and positive(row['retained_logical_bytes_peak'], 0, 48*MIB) >= row['high_water_sum'],
        'COMPONENT_ROOT_RETAINED_OBJECT_PEAK')
    high_water = 0
    for obj in row['objects']:
        same([obj[k] for k in ('handles', 'pending_opens', 'shm_references')], [0, 0, 0])
        require(obj['reserved_pending_open'] is False and type(obj['linked']) is bool,
                'COMPONENT_PENDING_ROOT_OBJECT')
        size = positive(obj['actual_last_bytes'], 0, 16*MIB)
        high_water += positive(obj['high_water_bytes'], size, 16*MIB)
        if obj['linked']:
            path = 'raw/'+ROLES[index]+'/'+obj['basename']
            require(path in bundle.files and bundle.files[path]['bytes'] == size,
                    'COMPONENT_LINKED_ROOT_BYTES_MISMATCH')
            original.live_original_identity(bundle, path,
                dict(device=obj['device'], inode=obj['inode']), False)
    same(high_water, row['high_water_sum'])
    require(len(row['lifecycle']) <= 1024 and len(row['cleanup_lifecycle']) <= 256
        and positive(row['lifecycle_serialized_bytes']) <= row['lifecycle_serialized_bytes_cap'] == 655360,
        'COMPONENT_ORIGINAL_LIFECYCLE_BOUNDS')
    events = row['lifecycle']+row['cleanup_lifecycle']
    sequences = [positive(event['sequence']) for event in events]
    same(sorted(sequences), list(range(len(events))))
    return index


def durable_packets(bundle, directory, facts):
    """Read a private WAL-aware copy; never open producer storage for SQLite I/O."""
    with tempfile.TemporaryDirectory(prefix='pn1-component-read-') as temp:
        root = Path(temp)
        for suffix in ('', '-wal', '-shm'):
            path = directory+'/native.sqlite'+suffix
            if path in bundle.files: (root/('native.sqlite'+suffix)).write_bytes(bundle.raw(path, 16*MIB))
        require((root/'native.sqlite').exists(), 'COMPONENT_ACTUAL_SQLITE_MISSING')
        with closing(sqlite3.connect((root/'native.sqlite').as_uri()+'?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.set_progress_handler(lambda: 1, 10_000_000)
            require(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'COMPONENT_SQLITE_INTEGRITY')
            rows = list(db.execute('SELECT id,parent,height,packet,state_root,chainwork FROM blocks ORDER BY height'))
            same(len(rows), len(facts)+1)
            require(rows[0][0] == facts[0]['header']['parent'] and rows[0][2] == 0,
                    'COMPONENT_ACTUAL_GENESIS_BINDING')
            work = 0
            for row, fact in zip(rows[1:], facts):
                work += 2**256 // (int.from_bytes(fact['header']['target'], 'big')+1)
                same([row[0].hex(), row[1], row[2], row[3].hex(), row[4], row[5]],
                     [fact['identity'], fact['header']['parent'], fact['header']['height'],
                      fact['wire'], fact['header']['state'], work.to_bytes(64, 'big')])
            tip, generation = db.execute('SELECT tip,generation FROM active WHERE singleton=1').fetchone()
            same([tip.hex(), generation], [facts[-1]['identity'], len(facts)])


def phase_readback(bundle, value, facts, caller, executable, native_pid, resources):
    require(value['schema'] == component.NATIVE_SCHEMA and value['kind'] == 'phase'
        and value['mode'] == MODE and value['parent_pid'] == native_pid,
        'COMPONENT_FINITE_PHASE_IDENTITY')
    same(value['plan'], component.PLAN)
    group = '0::'+resources['cgroup']+'\n'
    same(value['controller_cgroup'], group)
    component_process_limits(bundle.json('raw/process-limits.json'), 'campaign-parent', group, native_pid)
    for stage in ('prefix', 'pressure'):
        start, end = positive(value[stage+'_epoch_ns']), positive(value[stage+'_end_ns'])
        same(end-start, component.PLAN[stage+'_seconds']*1_000_000_000)
        same(bundle.json(PHASE+stage+'-start.json'),
             dict(schema=component.NATIVE_SCHEMA, epoch_ns=start, end_ns=end))
    previous = original.flow(value['initial_flow'], settled=True)
    initial_work, post_prefix_work, final_work = [
        original.completion_work_observation(value[key])
        for key in ('initial_work', 'post_prefix_work', 'final_work')]
    same(initial_work['retained_identities'], 0)
    same([initial_work['full_capacity_skips'], initial_work['repeated_identity_skips']], [0, 0])
    for key in ('post_prefix_flow', 'pressure_final_flow', 'final_flow'):
        current = original.flow(value[key], settled=key == 'final_flow')
        original.monotone(previous, current)
        previous = current
    same(post_prefix_work['retained_identities'], 2)
    same(final_work['retained_identities'], 6)
    require(len(value['children']) == len(value['actor_readiness']) == 2,
            'COMPONENT_TWO_ACTUAL_ACTORS_REQUIRED')
    pids, identities, bodies = set(), set(), []
    for worker, child in enumerate(value['children']):
        path = PHASE+f'actor-{worker:02}/'
        job, ready, result, finished = [bundle.json(path+name) for name in
            ('job.json', 'ready.json', 'report.json', 'prefix-finished.json')]
        for kind, row in (('ready', ready), ('child', child),
                          ('result', result), ('finished', finished)):
            original.v2_identity_types(kind, row)
        same(job['plan'], component.PLAN)
        same(job['worker'], worker)
        require(job['schema'] == 'native-public-v3-identity-actor-job-v2'
            and job['worker'] == worker and job['mode'] == MODE
            and job['template_packet'] == facts[4]['wire'], 'COMPONENT_ACTOR_ORIGINAL_INPUTS')
        same([job['source_commit'], job['source_tree'], job['binary_sha256']],
             [value['source_commit'], value['source_tree'], executable['sha256']])
        require(ready['schema'] == result['schema'] == finished['schema'] == component.ACTOR_SCHEMA
            and ready['worker'] == result['worker'] == finished['worker'] == worker,
            'COMPONENT_ORIGINAL_ACTOR_METADATA_IDENTITY')
        same([ready['source_commit'], ready['source_tree'], ready['binary_sha256']],
             [value['source_commit'], value['source_tree'], executable['sha256']])
        require(ready['setup_calls'] == 1 and ready['producer'] == 'prepared-generic',
                'COMPONENT_ORIGINAL_ACTOR_PRODUCER_SETUP')
        for row, keys in ((ready, ('setup_cpu_ns', 'setup_wall_ns')),
                         (result, ('prefix_cpu_ns', 'pressure_cpu_ns',
                                   'entire_actor_cpu_ns', 'entire_actor_wall_ns'))):
            for key in keys:
                original.integer(row[key], 1)
        # This profile records a held phase-FD pathname, whose actual inode is
        # independently checked below. The old full reader remains unchanged.
        phase_fd = positive(child['execution_binding']['binding']['fds'][1], 3)
        logical = '/proc/self/fd/'+str(phase_fd)
        same([job['output'], job['prefix_marker'], job['pressure_marker']],
             [logical+f'/actor-{worker:02}', logical+'/prefix-start.json', logical+'/pressure-start.json'])
        pid = positive(ready['pid'], 1)
        require(pid not in pids and pid != native_pid and ready['ppid'] == native_pid
            and child['pid'] == result['pid'] == finished['pid'] == pid
            and child['exit_success'] is True and child['parent_forced_kill'] is False
            and positive(child['reaped_ns']) >= positive(child['started_ns'])
            and ready['cgroup'] == result['cgroup'] == group, 'COMPONENT_CHILD_TERMINAL_OR_IDENTITY')
        pids.add(pid)
        same(child['ready'], ready)
        same(child['report'], result)
        same(child['prefix_finished'], finished)
        same(value['actor_readiness'][worker], ready)
        same(finished['slots'], result['prefix_slots'])
        component_process_limits(bundle.json(path+'process-limits.json'), 'actor', group, pid)
        original.descendant_actor_record(bundle, path, PHASE, child['execution_binding'],
            ready['execution_binding'], job, caller=caller['value'], executable=executable,
            parent_pid=native_pid, original_root_identity=identity(os.fstat(bundle.fd)))
        require(child['log_capture']['cap_reached'] is False
            and child['log_capture']['io_error'] is None, 'COMPONENT_ACTOR_LOG_INCOMPLETE')
        actor_cpu = 0
        for stage, count in (('prefix', 1), ('pressure', 2)):
            slots = result[stage+'_slots']
            same(len(slots), count)
            consumed = set()
            for slot, offered in enumerate(slots):
                offset = component.PLAN['prefix_calls_per_actor'] if stage == 'pressure' else 0
                index = (slot+offset)*component.PLAN['actors']+worker
                require(offered['status'] == 'called' and offered['slot'] == slot
                    and offered['index'] == index, 'COMPONENT_ORIGINAL_PAID_SLOTS_REQUIRED')
                stem = stage+f'/{index:05}'
                started = bundle.json(path+stem+'-started.json')
                require(started['index'] == index and started['template_header'] == facts[4]['wire'][:636],
                        'COMPONENT_STARTED_ATTEMPT_BINDING')
                material = bundle.json(path+stem+'-construction.json')
                packet, complete_id = original.construction(material, facts[4]['wire'], index, version='v2')
                require(packet is not None and complete_id not in identities,
                        'COMPONENT_REAL_UNIQUE_PAID_WINNER_REQUIRED')
                identities.add(complete_id)
                actor_cpu += material['construction_thread_cpu_ns']
                wrapper = bundle.json(path+stem+'-call.json')
                require(wrapper['schema'] == component.ACTOR_SCHEMA and wrapper['worker'] == worker
                    and wrapper['stage'] == stage and wrapper['index'] == index
                    and wrapper['construction_ref'] == stem+'-construction.json'
                    and offered['file'] == stem+'-call.json', 'COMPONENT_CALL_ACTUAL_MATERIAL_BINDING')
                epoch, end = value[stage+'_epoch_ns'], value[stage+'_end_ns']
                body = original.call(wrapper['call'], epoch=epoch, end=end)
                expected_body = H('public-request-body-v3', json.dumps(
                    dict(op='submit', packet=packet.hex()), separators=(',', ':')).encode()).hex()
                require(body == expected_body and wrapper['call']['status'] == 'refused'
                    and wrapper['call']['response']['value']['error'] == 'ROOT'
                    and wrapper['call']['returned_after_window'] is False,
                    'COMPONENT_ORIGINAL_ROOT_REFUSAL_OR_DEADLINE')
                same(wrapper['absolute_started_ns'], epoch+wrapper['call']['started_ns'])
                same(wrapper['absolute_ended_ns'], epoch+wrapper['call']['ended_ns'])
                bodies.append(body)
                consumed.update(path+stem+suffix for suffix in ('-started.json', '-construction.json', '-call.json'))
            same({name for name in bundle.files if name.startswith(path+stage+'/')}, consumed)
        require(actor_cpu <= result['prefix_cpu_ns']+result['pressure_cpu_ns']
            and result['entire_actor_cpu_ns'] >= ready['setup_cpu_ns']+result['prefix_cpu_ns']+result['pressure_cpu_ns'],
            'COMPONENT_ACTOR_CPU_DENOMINATOR')
    observed, accepted = original.receiver(value['receiver_observation'], bodies,
                                          value['final_flow'], value['service_outcome']['Ok'])
    same(Counter(accepted), Counter(bodies))
    same(sum(observed.values()), 6)
    require(value['paid_settled'] is value['service_thread_joined'] is value['cold_equal'] is True,
            'COMPONENT_OWNER_SERVICE_OR_COLD_CLOSE')
    honest = value['honest']
    same([honest[key] for key in ('submissions', 'history', 'confirmations', 'verifier_errors')], [[], [], [], []])
    require(honest['all_signed_rounds_confirmed_in_window'] is False,
            'FINITE_CONTROL_IS_NOT_THREE_ROUND_ACCEPTANCE')
    same(honest['client_final_tip'], facts[3]['identity'])
    same(value['initial_tip'], facts[3]['identity'])
    same(value['final_tip'], facts[3]['identity'])
    for row in value['hostile_candidates']:
        require(row['live_absent'] is row['cold_absent'] is True, 'COMPONENT_HOSTILE_DURABLE_PACKET')
    same(len(value['hostile_candidates']), 6)
    return sorted(pids)


def validate(folder, inventory_sha, prepared_path, prepared_sha, prepared_inventory, head, tree):
    source = component.PreparedComponent(prepared_path, prepared_sha, prepared_inventory, head, tree)
    fd = claim_fd = None
    bundle = None
    try:
        fd = held_directory(folder)
        bundle = component.ComponentBundle(folder, inventory_sha, directory_fd=fd, kind='execute')
        result = bundle.json('results.json')
        require(result['schema'] == component.EXECUTION and result['profile'] == component.PROFILE
            and result['complete_success'] is result['selector_executed'] is True
            and result['failure'] is None and result['component_readback_complete'] is False,
            'COMPONENT_COMPLETE_PRODUCER_PROCESS_REQUIRED')
        same([result['head'], result['tree'], result['prepared_sha256'], result['inventory_sha256']],
             [head, tree, prepared_sha, prepared_inventory])
        same(result['plan'], component.PLAN)
        same(result['evidence_caps'], component.CAPS)
        flags(result)
        link = bundle.json('prepared-claim-link.json')
        claim_fd = os.open(component.claim_name(source), os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                           dir_fd=source.parent_fd)
        same(set(held_file_names(claim_fd)), {'owner.lock', 'claim.json', 'terminal.json'})
        claim_pins = {name: checked_member(claim_fd, name)[0] for name in held_file_names(claim_fd)}
        require(claim_pins['owner.lock']['bytes'] == 0, 'COMPONENT_CLAIM_LOCK_BYTES')
        claim = strict_json(checked_member(claim_fd, 'claim.json', retain=True)[1])
        terminal = strict_json(checked_member(claim_fd, 'terminal.json', retain=True)[1])
        same(claim, bundle.json('claim-observed.json'))
        same(terminal, bundle.json('claim-terminal-observed.json'))
        require(link['schema'] == component.LINK and link['domain'] == component.DOMAIN
            and claim['schema'] == component.CLAIM and terminal['schema'] == component.TERMINAL
            and claim['domain'] == terminal['domain'] == component.DOMAIN,
            'COMPONENT_ORIGINAL_CLAIM_DOMAIN')
        binding = dict(source.binding, execution_root=str(folder),
            execution_identity=identity(os.fstat(bundle.fd)), claim_identity=identity(os.fstat(claim_fd)))
        same(link['binding'], binding)
        same(claim['binding'], binding)
        same(terminal['binding'], binding)
        same(link['claim_pin'], claim_pins['claim.json'])
        same(terminal['claim_sha256'], claim_pins['claim.json']['sha256'])
        require(terminal['dispatch_attempted'] is terminal['child_owner_called']
            is terminal['child_exit_observed'] is terminal['native_owner_success'] is True
            and type(terminal['returncode']) is int and terminal['returncode'] == 0 and terminal['failure'] is None,
            'COMPONENT_REAL_NATIVE_TERMINAL_REQUIRED')
        for row in (claim, terminal, link): flags(row)
        for name, pin in source.pins().items():
            same({k:bundle.files['frozen/'+name][k] for k in ('bytes', 'sha256')},
                 {k:pin[k] for k in ('bytes', 'sha256')})
        ledger = original.linked_evidence_ledger_v2(bundle.files, bundle.manifest_bytes,
            source.pins(), claim_pins, component.CAPS, strict=False)
        require(not original.evidence_ledger_v2(bundle.files, bundle.manifest_bytes,
            component.CAPS, strict=False)['retained_failure_files'], 'COMPONENT_RETAINED_FAILURE_OR_PARTIAL')
        step = bundle.json('component.step.json')
        component.validate_step(bundle, step)
        same(step, result['step'])
        native_pid = child_terminal(step['native_process_owner'], 0)
        same(step['command'], [str(folder/'frozen'/(component.TARGET+'.bin')), '--exact',
             component.SELECTOR, '--ignored', '--nocapture', '--test-threads=1'])
        same(step['outer_stage_timeout_seconds'], component.RUN_SECONDS)
        stdout = bundle.raw(step['stdout']).decode('utf-8')
        require(len(re.findall(r'^running 1 test$', stdout, re.M)) == 1
            and re.search(r'^test '+component.SELECTOR+r' \.\.\. ok$', stdout, re.M)
            and len(re.findall(r'^test result:', stdout, re.M)) == 1
            and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', stdout, re.M),
            'COMPONENT_EXACT_ORIGINAL_FINITE_SELECTOR_REQUIRED')
        resources = bundle.json('resource-before.json')
        for name in ('resource-before.json', 'resource-after.json'):
            component.validate_resources(bundle.json(name), 10)
            same(bundle.json(name)['cgroup'], resources['cgroup'])
        for label in ('source-before', 'source-after'):
            source_row = bundle.json(label+'.json')
            source_step = bundle.json(label+'.step.json')
            component.validate_step(bundle, source_step)
            same(source_row, strict_json(bundle.raw(source_step['stdout'])))
            require(source_row['tested_commit'] == head and source_row['tested_tree'] == tree
                and source_row['tracked_worktree_verified'] is True, 'COMPONENT_EXACT_SOURCE_CAPTURE')
            require(result['post_observations'][label.split('-')[0]]['success'] is True,
                    'COMPONENT_POST_SOURCE_UNKNOWN')
        for label in ('inputs', 'source', 'resources'):
            same(result['post_observations'][label], dict(success=True, failure=None))
        top, plan = bundle.json('raw/report.json'), bundle.json('raw/plan.json')
        require(top['schema'] == component.NATIVE_SCHEMA and top['native_mechanism_complete'] is True,
                'COMPONENT_NATIVE_MECHANISM_INCOMPLETE')
        same(top['plan'], component.PLAN)
        flags(top)
        same(plan['execution_caller']['parent_pid'], native_pid)
        executable = first_dispatch(bundle, step['fd_dispatch'], plan['execution_caller'], native_pid,
                                    source.value['binary'])
        facts = seed_facts(bundle.json('raw/preparation.json'))
        same(len(top['phases']), 1)
        require(top['phases'][0]['mode'] == MODE and top['phases'][0]['error'] is None,
                'COMPONENT_ONE_ORIGINAL_FINITE_PHASE')
        phase = bundle.json(PHASE+'report.json')
        same([phase['source_commit'], phase['source_tree'], phase['binary_sha256']],
             [head, tree, executable['sha256']])
        pids = phase_readback(bundle, phase, facts,
            dict(value=plan['execution_caller'], raw_root=step['fd_dispatch']['actual_raw_root']),
            executable, native_pid, resources)
        roles = bundle.json('raw/preparation.json')['native_io_terminal_roots']+phase['native_io_terminal_roots']
        same(sorted(root_terminal(bundle, row, native_pid, top['native_io_storage']) for row in roles), [0, 5, 6])
        durable_packets(bundle, 'raw/honest-miner', facts)
        for index in (5, 6): durable_packets(bundle, 'raw/'+ROLES[index], facts[:4])
        bundle.recheck()
        source.recheck()
        return dict(schema=SCHEMA, profile=component.PROFILE, mechanism_readback_complete=True,
            actual_parent_pid=native_pid, actual_actor_pids=pids, actual_used_Node_roles=[0, 5, 6],
            prefix_paid_unique=2, final_paid_unique=6, ledger=ledger,
            scope='retained original finite local component; trusted operator/toolchain/input, no host attestation',
            **component.component_flags())
    finally:
        if bundle is not None: bundle.close()
        if fd is not None: os.close(fd)
        if claim_fd is not None: os.close(claim_fd)
        source.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'prepared'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('inventory-sha256', 'prepared-sha256', 'prepared-inventory-sha256', 'expected-head', 'expected-tree'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(component.canonical(args.out), args.inventory_sha256,
        component.canonical(args.prepared), args.prepared_sha256, args.prepared_inventory_sha256,
        args.expected_head, args.expected_tree), sort_keys=True))


if __name__ == '__main__': main()
