#!/usr/bin/env python3
"""Strict readback of the source-bound, actually isolated public History actor.

These checks bind retained reports to actual IPC bytes and original raw phases.
They cannot authenticate a remote host independently of the pinned native run,
turn caller supplied counters into authority, or qualify production activation.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

PARENT = '/sys/fs/cgroup/trnmponpublic.slice'
SCHEMA = 'native-public-history-verifier-process-v2'
STRICT_PROFILE = 'strict-every-native-checkpoint-v1'
GRAPH_PROFILE = 'history-account-graph-resource-fence-v1'
GRAPH_SCHEMA = 'native-public-history-verifier-graph-fence-process-v1'
GRAPH_ENTRY_SCHEMA = 'native-public-history-verifier-graph-fence-entry-v1'
GRAPH_COUNTERS = ('imports', 'imports_closed', 'imports_failed', 'native_cpu_checkpoints',
                  'graph_entries', 'graph_exits', 'graph_aborts', 'graph_node_checkpoints',
                  'graph_completed_node_bodies', 'graph_full_resource_checks', 'graph_max_node_window',
                  'before_commit_checks', 'scope_failures', 'unfinished_scopes', 'kernel_checks',
                  'kernel_failed_checks', 'kernel_cpu_known_calls', 'kernel_cpu_unknown_calls',
                  'kernel_cpu_ns', 'kernel_wall_ns', 'binding_checks', 'binding_failed_checks')
LIMITS = {'cpu.max': '25000 100000', 'cpu.max.burst': '0',
          'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'}
COUNTERS = ('usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec')
MAX_BYTES = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and value >= 0, 'actual nonnegative integer required')
    return value


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
            'exact lowercase SHA256 required')
    return value


def native_hash(value):
    require(type(value) is list and len(value) == 32
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value),
            'exact native 32-byte hash required')
    return bytes(value).hex()


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular retained IPC file required')
    require(path.stat().st_size <= MAX_BYTES, 'bounded retained IPC required')
    raw = path.read_bytes()
    require(len(raw) <= MAX_BYTES, 'bounded actual IPC bytes required')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate IPC key refused')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite IPC')))
    return value, hashlib.sha256(raw).hexdigest()


def parent_identity(value):
    require(value['path'] == PARENT and value['uid'] == 0,
            'one original root-owned fixed parent required')
    require(integer(value['mode']) & 0o022 == 0, 'fixed parent must not be writable by caller')
    require(integer(value['mode']) & 0o170000 == 0o040000, 'fixed parent directory required')
    require({key: value[key] for key in LIMITS} == LIMITS,
            'original fixed quarter-CPU memory/swap/tasks limits required')
    require(integer(value['inode']) > 0 and integer(value['device']) > 0,
            'actual fixed parent filesystem identity required')
    require(type(value['boot_id']) is str
            and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']),
            'actual boot identity required')
    integer(value['memory.current'])
    require(integer(value['pids.current']) <= 256, 'observed fixed parent task ceiling')
    for key in COUNTERS:
        integer(value['cpu.stat'][key])
    return tuple(value[key] for key in ('device', 'inode', 'boot_id'))


def graph_observation(value):
    require(value['schema'] == 'ordinary-history-graph-resource-observation-v1'
            and value['profile'] == GRAPH_PROFILE
            and type(value['maximum_node_bodies_between_full_checks']) is int
            and value['maximum_node_bodies_between_full_checks'] == 8
            and value['strict_path_is_separate'] is True
            and value['observation_is_authority'] is False
            and value['wall_clock_revocation_bound_claimed'] is False,
            'explicit ordinary N8 observation without authority or wall-clock claim required')
    counters = value['counters']
    require(type(counters) is dict and set(counters) == set(GRAPH_COUNTERS), 'complete exact N8 counter schema')
    for key in GRAPH_COUNTERS:integer(counters[key])
    require(counters['imports_closed'] <= counters['imports']
            and counters['imports_failed'] <= counters['imports']
            and counters['graph_aborts'] <= counters['graph_exits'] <= counters['graph_entries']
            and counters['graph_completed_node_bodies'] <= counters['graph_node_checkpoints']
            and counters['graph_node_checkpoints'] <= counters['native_cpu_checkpoints']
            and counters['graph_max_node_window'] <= 8,
            'actual bounded graph and import counters required')
    require(counters['kernel_checks'] == counters['kernel_cpu_known_calls'] + counters['kernel_cpu_unknown_calls']
            and counters['kernel_failed_checks'] <= counters['kernel_checks']
            and counters['binding_failed_checks'] <= counters['binding_checks'],
            'complete instrumented current-read and binding accounting required')
    require(counters['kernel_cpu_unknown_calls'] == 0, 'unknown inner kernel CPU is not zero')
    if counters['kernel_checks']:
        require(counters['kernel_cpu_ns'] > 0 and counters['kernel_wall_ns'] > 0,
                'actual instrumented inner kernel costs required')
    else:
        require(counters['kernel_cpu_ns'] == counters['kernel_wall_ns'] == 0, 'no kernel calls cannot claim CPU')
    if 'live_known_close_pending' in value:
        require(type(value['live_known_close_pending']) is bool
                and value['cold_epoch_recovery_granted'] is False, 'live pending is not cold debt authority')
    return counters


def validate_phase(phase, directory, binary_sha256, outer_cgroup, expected_profile=STRICT_PROFILE):
    require(expected_profile in (STRICT_PROFILE, GRAPH_PROFILE), 'explicit supported History resource profile')
    digest(binary_sha256)
    value = phase['history_verifier_process']
    expected_schema = GRAPH_SCHEMA if expected_profile == GRAPH_PROFILE else SCHEMA
    require(value['schema'] == expected_schema, 'mandatory real verifier process boundary')
    require(value['completed_successfully'] is True and value['exit_success'] is True
            and value['parent_forced_kill'] is False, 'actual clean verifier exit required')
    require(value['outer_process_cpu_excludes_verifier'] is True,
            'separate verifier process CPU must not be relabeled parent CPU')
    require(type(outer_cgroup) is str and outer_cgroup.startswith('/')
            and not outer_cgroup.startswith('/trnmponpublic.slice'),
            'original independent outer campaign cgroup required')
    require(value['original_outer_cgroup'] == outer_cgroup,
            'verifier must not move the original four-CPU campaign')
    unit = value['unit']
    require(type(unit) is str and re.fullmatch(r'trnm-campaign-verifier-[1-9][0-9]*-[1-9][0-9]*\.service', unit),
            'one uniquely named actual verifier service required')
    cgroup = '/trnmponpublic.slice/' + unit
    ready = value['ready']
    report = value['report']
    entry = report['result']
    retained_ready, _ = read(Path(directory) / 'ready.json')
    retained_report, _ = read(Path(directory) / 'report.json')
    job, _ = read(Path(directory) / 'job.json')
    profiles = [item.get('history_resource_profile') for item in (phase, value, job, ready, entry)]
    historical_strict = all(item is None for item in profiles)
    require((historical_strict and expected_profile == STRICT_PROFILE
             and 'history_graph_resource' not in ready and 'history_graph_resource' not in entry)
            or all(item == expected_profile for item in profiles),
            'job, phase, process, ready and entry must bind the requested resource profile')
    previous_graph = None if historical_strict else graph_observation(ready['history_graph_resource'])
    if previous_graph is not None:
        require(not any(previous_graph.values()), 'fresh actual verifier begins without imported graph work')
    require(retained_ready == ready and retained_report == report,
            'complete actual ready/exit report bytes must match raw phase')
    require(job['kind'] == 'history-verifier' and job['parent'] == PARENT
            and job['binary_sha256'] == binary_sha256
            and job['backend'] == phase['state_backend']
            and job['owner_death_control'] is None
            and type(job['seed']) is list and len(job['seed']) == 4,
            'exact original verifier job, seed count and backend required')
    # These fields bind retained observations to the exact native run. They
    # never turn a numeric PID or caller JSON into the actual owner capability.
    owner = job['controller_observation']
    require(type(owner) is dict and set(owner) == {'pid', 'uid', 'gid'},
            'complete observed controller identity required')
    require(integer(owner['pid']) > 1
            and all(integer(owner[key]) <= 0xffffffff for key in ('uid', 'gid')),
            'actual controller process and credential observations required')
    require(unit.startswith('trnm-campaign-verifier-' + str(owner['pid']) + '-'),
            'actual controller observation must match its service unit')
    lifeline = ready['controller_lifeline']
    require(lifeline == entry['controller_lifeline'],
            'same actual owner watch before Node open and after Node close required')
    require(lifeline['schema'] == 'native-history-controller-lifeline-v1'
            and lifeline['capability'] == 'anonymous-unix-stream+prequeued-self-pidfd'
            and lifeline['controller'] == owner
            and lifeline['armed_before_node_open'] is True
            and lifeline['watch_until_process_exit'] is True,
            'prequeued private owner capability and whole-process watcher required')
    pid = integer(ready['pid'])
    require(pid > 1 and entry['pid'] == pid, 'one actual native verifier process required')
    require(ready['cgroup'] == cgroup and entry['cgroup'] == cgroup
            and ready['calling_thread_cgroup'] == '0::' + cgroup,
            'actual verifier and calling thread must remain in the fixed parent')
    require(ready['public_host_kernel_checked'] is True
            and ready['wrong_parent_refused'] is True,
            'actual original checker and wrong-parent refusal required')
    require(report['kind'] == 'history-verifier' and report['error'] is None
            and entry['schema'] == (GRAPH_ENTRY_SCHEMA if expected_profile == GRAPH_PROFILE
                                    else 'native-public-history-verifier-entry-v2')
            and entry['clean_node_close'] is True, 'actual original Node close required')
    for observed in (value['binary_sha256'], ready['binary_sha256'], entry['binary_sha256']):
        require(digest(observed) == binary_sha256, 'same retained release binary required')
    points = [value['parent_before_spawn'], entry['parent_before'], ready['parent'],
              entry['parent_after_node_close'], value['parent_after_reap']]
    identities = [parent_identity(point) for point in points]
    require(len(set(identities)) == 1, 'fixed parent replacement or reboot refused')
    require(points[0]['pids.current'] == points[-1]['pids.current'] == 0,
            'actual sole verifier parent must be empty before spawn and after reap')
    require(all(point['pids.current'] > 0 for point in points[1:-1]),
            'real live verifier task observations required')
    for before, after in zip(points, points[1:]):
        require(all(before['cpu.stat'][key] <= after['cpu.stat'][key] for key in COUNTERS),
                'actual fixed parent cumulative counters may not rewind')
    kernel_cpu_ns = (points[-1]['cpu.stat']['usage_usec'] - points[0]['cpu.stat']['usage_usec']) * 1000
    require(kernel_cpu_ns > 0, 'actual whole-parent verifier CPU required')
    whole_cpu = integer(entry['whole_verifier_process_cpu_ns'])
    require(0 < whole_cpu <= integer(entry['process_cpu_since_start_ns']),
            'actual process CPU through original Node close required')
    require(integer(report['whole_entry_cpu_ns']) >= whole_cpu,
            'outer entry must include the original verifier operation scope')
    require(integer(ready['setup_process_cpu_ns']) > 0, 'actual seed/setup CPU required')
    calls = entry['calls']
    require(type(calls) is list and 2 <= len(calls) <= 132
            and value['request_count'] == len(calls), 'bounded complete IPC sequence required')
    require([call['operation'] for call in calls[-2:]] == ['snapshot', 'finish'],
            'actual final snapshot and clean finish required')
    require(sum(call['operation'] == 'import' for call in calls) <= 64
            and sum(call['operation'] == 'confirmation' for call in calls) <= 3,
            'original import and round caps may not increase')
    for prefix in ('request', 'response'):
        require({path.name for path in Path(directory).glob(prefix + '-*.json')}
                == {f'{prefix}-{sequence:03}.json' for sequence in range(len(calls))},
                'every retained IPC sequence must be accounted for exactly once')
    call_cpu = 0
    imported = {}
    confirmed = {}
    for sequence, call in enumerate(calls):
        require(call['sequence'] == sequence, 'missing duplicate or reordered verifier sequence')
        operation = call['operation']
        require(operation in ('import', 'confirmation', 'snapshot', 'finish'),
                'unknown verifier operation refused')
        if sequence < len(calls) - 2:
            require(operation in ('import', 'confirmation'), 'early finalization refused')
        request, request_sha = read(Path(directory) / f'request-{sequence:03}.json')
        response, response_sha = read(Path(directory) / f'response-{sequence:03}.json')
        require(request['sequence'] == response['sequence'] == sequence
                and request['operation'] == operation, 'actual request/response sequence binding')
        require(digest(call['request_sha256']) == response['request_sha256'] == request_sha
                and digest(call['response_sha256']) == response_sha,
                'actual original IPC bytes must match both recorded digests')
        require(response['binary_sha256'] == binary_sha256, 'response source binary binding')
        require(call['succeeded'] == (response['error'] is None), 'native failure cannot be relabeled success')
        measurement = call['measurement']
        require(measurement == response['measurement']
                and measurement['process_id'] == pid and measurement['sequence'] == sequence,
                'exact actual verifier process measurement required')
        require(measurement['thread_cpu_observation_available'] is True,
                'actual calling thread CPU must be observed')
        call_cpu += integer(measurement['process_cpu_ns'])
        integer(measurement['thread_cpu_ns'])
        integer(measurement['process_wall_ns'])
        if historical_strict:
            require('history_resource_profile' not in measurement and 'history_graph_resource' not in measurement,
                    'historical strict data cannot mix a new profile into later calls')
        else:
            require(measurement['history_resource_profile'] == expected_profile, 'per-call resource profile binding')
            current_graph = graph_observation(measurement['history_graph_resource'])
            require(all(current_graph[key] >= previous_graph[key] for key in GRAPH_COUNTERS),
                    'actual cumulative graph observations cannot rewind')
            if expected_profile == STRICT_PROFILE:
                require(not any(current_graph.values()), 'strict importer cannot silently use the N8 profile')
            previous_graph = current_graph
        if operation == 'import':
            require(request['source'] == phase['address'], 'original concrete source address required')
            imported[sequence] = (request, response)
        elif operation == 'confirmation':
            confirmed[sequence] = (request, response)
        elif operation == 'snapshot':
            require(response['error'] is None, 'actual final native snapshot must succeed')
            active = response['value']['active']
            require(type(active) is list and len(active) == 3
                    and native_hash(active[0]) == digest(phase['final_client_tip']),
                    'actual snapshot tip must match the original final client tip')
    require(integer(ready['setup_process_cpu_ns']) + call_cpu <= whole_cpu,
            'disjoint setup/call process CPU cannot exceed whole verifier CPU')
    actual_imports = {}
    actual_confirmations = {}
    rounds = phase['confirmations']
    require(type(rounds) is list, 'original confirmation rounds required')
    matched_rounds = set()
    for row in phase['history']:
        if 'client_import' in row:
            sequence = integer(row['client_import']['sequence'])
            require(sequence in imported and sequence not in actual_imports,
                    'raw history must reference each actual importer once')
            request, response = imported[sequence]
            require(request['page'] == row['response']['value'], 'exact original Page bytes/value required')
            original = row['request']
            require(original['op'] == 'history'
                    and native_hash(request['tip']) == digest(original['tip'])
                    and native_hash(request['after']) == digest(original['after']),
                    'actual import target and cursor must match the original History request')
            for key, measurement in response['measurement'].items():
                require(row['client_import'][key] == measurement, 'raw import process receipt mismatch')
            require(row['client_import']['succeeded'] == (response['error'] is None),
                    'raw import outcome mismatch')
            actual_imports[sequence] = True
        if 'client_confirmation' in row:
            sequence = integer(row['client_confirmation']['sequence'])
            require(sequence in confirmed and sequence not in actual_confirmations,
                    'raw confirmation must reference its actual native call once')
            request, response = confirmed[sequence]
            for key, measurement in response['measurement'].items():
                require(row['client_confirmation'][key] == measurement, 'raw confirmation receipt mismatch')
            require(row['client_confirmation']['succeeded'] is (response['error'] is None),
                    'raw confirmation outcome mismatch')
            transaction = native_hash(request['transaction'])
            included = native_hash(request['included'])
            matching = [index for index, round_ in enumerate(rounds)
                        if digest(round_['transaction']) == transaction
                        and digest(round_['included_block']) == included]
            require(len(matching) == 1 and matching[0] not in matched_rounds,
                    'actual confirmation must bind exactly one original round')
            index = matching[0]
            require(response['value'] == rounds[index]['observation'],
                    'actual native confirmation value must match the original round')
            matched_rounds.add(index)
            actual_confirmations[sequence] = True
    require(set(actual_imports) == set(imported) and set(actual_confirmations) == set(confirmed),
            'no hidden or substituted verifier work may be omitted from raw rows')
    require(all(round_['observation'] is None or index in matched_rounds
                for index, round_ in enumerate(rounds)),
            'every observed confirmation round must have its actual native call')
    require(phase['receiver_client_state_equal'] is True, 'actual full receiver/verifier state equality required')
    if not historical_strict:
        final_graph = graph_observation(entry['history_graph_resource'])
        require(final_graph == previous_graph and entry['history_graph_resource']['live_known_close_pending'] is False,
                'final observation must be the original closed Node observation')
        if expected_profile == GRAPH_PROFILE:
            require(final_graph['imports'] == len(imported) > 0
                    and final_graph['imports_closed'] == final_graph['imports']
                    and final_graph['graph_entries'] == final_graph['graph_exits'] > 0
                    and final_graph['unfinished_scopes'] == final_graph['scope_failures'] == 0
                    and final_graph['kernel_failed_checks'] == final_graph['binding_failed_checks'] == 0
                    and final_graph['before_commit_checks'] > 0
                    and final_graph['kernel_cpu_ns'] <= whole_cpu,
                    'actual complete N8 imports, original commit edges and nested measured CPU required')
    return {'schema': expected_schema, 'history_resource_profile': expected_profile, 'pid': pid, 'cgroup': cgroup,
            'request_count': len(calls), 'import_count': len(imported),
            'confirmation_count': len(confirmed), 'whole_fixed_parent_cpu_ns': kernel_cpu_ns,
            'whole_verifier_process_cpu_ns': whole_cpu,
            'process_cpu_since_start_ns': entry['process_cpu_since_start_ns'],
            'setup_process_cpu_ns': ready['setup_process_cpu_ns'],
            'call_process_cpu_ns': call_cpu, 'original_outer_cgroup': outer_cgroup,
            'cost_scopes_are_nested_not_additive': True,
            'all_ipc_bytes_read_back': True, 'independent_host_authentication': False,
            'production_qualification': False}


def validate_report(report, raw_directory, binary_sha256, outer_cgroup, expected_profile=STRICT_PROFILE):
    phases = report['phases']
    require([phase['mode'] for phase in phases] == ['baseline', 'from-zero', 'late-product'],
            'original three phases required')
    result = []
    for phase in phases:
        row = validate_phase(phase, Path(raw_directory) / phase['mode'] / 'independent-client',
                             binary_sha256, outer_cgroup, expected_profile)
        row['mode'] = phase['mode']
        result.append(row)
    return {'schema': 'native-public-history-verifier-three-phase-readback-v1',
            'phases': result, 'complete': True, 'history_resource_profile': expected_profile,
            'original_four_cpu_outer_budget_changed': False}
