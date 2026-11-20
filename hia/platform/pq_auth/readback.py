"""Read complete PQ qualification evidence without executing any tested image."""
from __future__ import annotations
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
import argparse
import gzip
import io
import json
import lzma
import math
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.qualification.contract import (ADAPTERS, COMPILER, LIBRARIES, LIMITS, PARTITIONS,
    PLATFORM_GUARD, PREFIX, REVISION, SCHEMA, UNITS, adapter_command, canonical, compose, document, identity,
    input_map, need, normalize, partition_cases, read, regular, relative, same, sha)
from hia.tools import ml_dsa_original, qualify_ml_dsa, toolchain


@contextmanager
def original_source(root):
    saved = qualify_ml_dsa.ROOT
    qualify_ml_dsa.ROOT = root
    try:
        yield
    finally:
        qualify_ml_dsa.ROOT = saved


def bound(root, name, expected):
    raw = read(root, name)
    need(type(expected) is dict and len(raw) == expected.get('bytes') and sha(raw) == expected.get('sha256'),
         'changed retained bytes: ' + name)
    return raw


def process_receipt(value, argv, cwd, limit, *, success=True):
    """Independent validation of recorded execution and group cleanup phases."""
    need(type(value) is dict and value.get('schema') == 'trnm.pq.process-supervision.v1'
         and value.get('policy') == 'absolute-execution-single-group-cleanup-v1'
         and value.get('argv') == list(map(str, argv)) and value.get('cwd') == str(cwd)
         and value.get('execution_limit_seconds') == limit and value.get('cleanup_limit_seconds') == 3
         and value.get('start_new_session') is True, 'changed supervision execution/cleanup contract')
    need(value.get('subreaper', {}).get('active') == 1 and value['subreaper']['previous'] in (0, 1),
         'process subreaper omitted')
    fields = ('started_monotonic', 'execution_deadline_monotonic', 'execution_finished_monotonic',
              'execution_seconds', 'cleanup_started_monotonic', 'cleanup_deadline_monotonic',
              'cleanup_finished_monotonic', 'cleanup_seconds', 'seconds')
    need(all(type(value.get(key)) in (int, float) and math.isfinite(value[key])
             and value[key] >= 0 for key in fields), 'invalid supervision clock')
    first, executed, cleanup_start, cleanup_end = (value[key] for key in
        ('started_monotonic', 'execution_finished_monotonic', 'cleanup_started_monotonic', 'cleanup_finished_monotonic'))
    need(first <= executed <= cleanup_start <= cleanup_end
         and value['execution_deadline_monotonic'] == first + limit
         and value['cleanup_deadline_monotonic'] == cleanup_start + 3
         and value['execution_seconds'] == executed - first and value['cleanup_seconds'] == cleanup_end - cleanup_start
         and value['seconds'] >= cleanup_end - first, 'changed supervision clock or reset cleanup deadline')
    attempts = value.get('killpg_attempts')
    need(type(attempts) is list and len(attempts) <= 1 and all(item.get('signal') == 9
         and type(item.get('errno')) is int and item['errno'] >= 0
         and cleanup_start <= item.get('monotonic', -1) <= cleanup_end for item in attempts),
         'repeated or unbound process-group cleanup')
    reaped = value.get('adopted_reaped')
    need(type(reaped) is list and len({row['pid'] for row in reaped}) == len(reaped)
         and all(type(row['pid']) is int and row['pid'] > 1 and type(row['wait_status']) is int
                 and type(row['exit_code']) is int for row in reaped), 'invalid adopted-child reap observation')
    if value['pid'] is not None:
        need(type(value['pid']) is int and value['pid'] > 1 and value['pgid'] == value['session_id'] == value['pid'],
             'process group/session is not the actual owned child')
    if success:
        need(value['outcome'] == 'success' and value['exit_code'] == 0 and value['timed_out'] is False
             and value['launch_error'] is None and value['execution_error'] is None
             and value['pid'] is not None and value['direct_child_reaped'] is True
             and value['group_absent'] is True and value['streams_complete'] is True
             and value['cleanup_complete'] is True and value['descendants_outlived_leader'] is False
             and attempts == [] and value['execution_seconds'] <= limit and value['cleanup_seconds'] <= 3,
             'incomplete or unsuccessful process supervision')


def stage(root, row, name, argv, cwd, limit, data=b'', *, supervised=True):
    need(row.get('name') == name and row.get('argv') == list(map(str, argv)) and row.get('cwd') == str(cwd)
         and row.get('wall_limit_seconds') == limit and row.get('exit_code') == 0 and row.get('timed_out') is False,
         'changed or unsuccessful stage: ' + name)
    need(same(row, document(read(root, name + '.receipt.json'))), 'stage receipt differs: ' + name)
    need(row.get('input_bytes') == len(data) and row.get('input_sha256') == sha(data)
         and read(root, name + '.stdin.raw') == data, 'stage request differs: ' + name)
    for stream in ('stdout', 'stderr'):
        need(row[stream]['path'] == name + '.' + stream + '.raw', 'stage output path differs')
        bound(root, row[stream]['path'], row[stream])
    need(type(row.get('seconds')) in (int, float) and 0 <= row['seconds'] <= limit + 10, 'invalid stage duration')
    if supervised:
        process_receipt(row.get('supervision'), argv, cwd, limit)
        need(row['exit_code'] == row['supervision']['exit_code'] and row['timed_out'] == row['supervision']['timed_out'],
             'stage result differs from actual supervisor')
        need(row['supervision']['seconds'] <= row['seconds'],
             'stage duration is shorter than actual supervisor')


def validate_native_build(root, source_root, sources, executed_repo, executed_out, python):
    directory = root / 'native'
    value = document(read(directory, 'build.json'))
    need(value.get('status') == 'PASS' and same(value.get('environment_guard'), ml_dsa_original.ENVIRONMENT_GUARD),
         'incomplete native build')
    need(same(value.get('platform_environment_guard'), PLATFORM_GUARD), 'native platform override policy omitted')
    need(same(value.get('source_before'), value.get('source_after')), 'native source changed')
    for name, row in value['source_before'].items():
        need(sources.get(relative(name)) == row['sha256'], 'native source is outside the frozen graph')
        need(bound(directory, 'inputs/' + name, row) == read(source_root, name), 'captured native input differs')
    tools = value['platform_tools']
    need(set(tools) == {'ld', 'objcopy', 'objdump', 'nm'}, 'native platform tools omitted')
    for row in tools.values():
        need(Path(row['path']).is_absolute() and type(row['bytes']) is int and row['bytes'] > 0
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'unbound native platform executable')
    need(len(value['builds']) == 4, 'native image roster omitted')
    expected_stages = [('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'], b'')]
    out = executed_out / 'native'
    native_calls = []
    saved_lock = toolchain.LOCK
    try:
        toolchain.LOCK = source_root / 'hia/toolchain.lock.json'
        upstream, _ = toolchain.pinned_toolchain()
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        for row, (name, source, symbol) in zip(value['builds'], UNITS):
            need(row['name'] == name, 'native image order changed')
            receipt = row['receipt']
            composed, captured = compose(source_root, source)
            need(read(directory, name + '.hepta') == composed, 'native composition changed')
            checked = assemble_program(composed)
            core = checked.as_dict()
            need(same(document(read(directory, name + '.core.json')), core), 'native Core differs from exact HIA source')
            functions = core['functions']
            operations = sum(len(block['ops']) for function in functions for block in function['blocks'])
            need(row['functions'] == len(functions) <= 128 and row['ops'] == operations <= 8192,
                 'native pinned resource budget changed')
            wire_core = checked.as_dict()
            wire_core['module'] = 'selfhost_elf'
            wire = render_assembly(wire_core).encode()
            ext = '.o' if symbol else '.so'
            artifact = read(directory, name + ext)
            need(receipt.get('schema') == 'trnm.hia.selfhost-build.v1' and receipt.get('ok') is True
                 and receipt.get('status') == 'native_emitted_not_executed'
                 and receipt.get('compiler_sha256') == COMPILER and receipt.get('compiler_wire_sha256') == sha(wire)
                 and receipt.get('output') == str(out / (name + ext)) and receipt.get('kind') == ('object' if symbol else 'shared')
                 and receipt.get('artifact_bytes') == len(artifact) and receipt.get('artifact_sha256') == sha(artifact)
                 and receipt.get('exports') == ['f0'] and receipt.get('borrowed_entry_profile') == 'legacy-f0-private-buffers'
                 and receipt.get('output_profile_selection') == 'selfhost_elf', 'native compiler receipt mismatch')
            need(same(receipt.get('claims'), {'direct_machine_code': True, 'external_linker_used': not bool(symbol),
                'fallback_used': False, 'python_emitter_used': False, 'self_hosted': True, 'whole_native_delivery_qualified': False}),
                'native build promoted a hosted fallback')
            migration = receipt['chain_migration']
            expected_inputs = {**captured, 'components.json': sources['hia/components.json']}
            need(type(migration.get('inputs')) is list and len(migration['inputs']) == len(expected_inputs)
                 and {item['path']: item['sha256'] for item in migration['inputs']} == expected_inputs
                 and migration['inputs'][0] == {'path': source[4:], 'sha256': sources[source]}
                 and migration.get('source_sha256') == sources[source] and migration.get('composed_source_sha256') == sha(composed)
                 and migration.get('core_sha256') == checked.sha256 and migration.get('toolchain_revision') == REVISION
                 and migration.get('toolchain_repository') == 'TrillionniumFoundation/Hepta'
                 and migration.get('backend') == 'selfhost' and migration.get('hosted_build_driver') is True
                 and migration.get('whole_chain_native') is False, 'native source/receipt closure differs')
            invocations = [item for item in value['native_invocations'] if item['unit'] == name]
            need(len(invocations) == (3 if symbol else 4), 'native subprocess roster changed')
            native_calls.extend(invocations)
            for index, invocation in enumerate(invocations):
                label = f'native-{name}-{index:02d}'
                need(invocation['name'] == label and same(invocation, document(read(directory, label + '.receipt.json')))
                     and invocation['exit_code'] == 0 and invocation['timed_out'] is False
                     and invocation['cwd'] == str(executed_repo), 'native subprocess failed or receipt changed')
                for stream in ('stdout', 'stderr'):
                    need(invocation[stream]['path'] == label + '.' + stream + '.raw', 'native stream path differs')
                    bound(directory, invocation[stream]['path'], invocation[stream])
                need(read(directory, label + '.stderr.raw') == b'', 'native subprocess stderr was nonempty')
                incoming = read(directory, label + '.stdin.raw')
                need(invocation['input_bytes'] == len(incoming) and invocation['input_sha256'] == sha(incoming), 'native request receipt differs')
                if index < 2:
                    command = ['git', '-C', str(upstream), 'rev-parse', 'HEAD'] if index == 0 else ['git', '-C', str(upstream), 'status', '--porcelain=v1', '--untracked-files=no']
                    need(invocation['argv'][0:2] == command[:2] and invocation['argv'][3:] == command[3:]
                         and invocation['wall_limit_seconds'] == 10 and invocation['environment'] is None
                         and invocation['pass_fds'] == [] and incoming == b'', 'changed toolchain identity command')
                    need(read(directory, label + '.stdout.raw') == (REVISION.encode() + b'\n' if index == 0 else b''),
                         'different or dirty actual pinned toolchain')
                elif index == 2:
                    need(len(invocation['argv']) == 1 and re.fullmatch(r'/proc/self/fd/[0-9]+', invocation['argv'][0])
                         and invocation['pass_fds'] == [int(invocation['argv'][0].rsplit('/', 1)[1])]
                         and invocation['wall_limit_seconds'] == 30 and invocation['environment'] == {'PATH': ''}
                         and invocation.get('executable_sha256') == COMPILER and incoming == wire,
                         'actual sealed native compiler invocation differs')
                    object_raw = read(directory, label + '.stdout.raw')
                    need(object_raw.startswith(b'\x7fELF\x02\x01') and sha(object_raw) == receipt['object_sha256'],
                         'native compiler stdout differs from its object')
                    if symbol:
                        need(object_raw == artifact, 'native object replaced after compilation')
                else:
                    argv = invocation['argv']
                    need(len(argv) == 18 and argv[:14] == ['ld', '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
                         '-z', 'relro', '-z', 'now', '--build-id=none', '--hash-style=both']
                         and Path(argv[14]).name == 'program.o' and argv[15:17] == ['-lc', '-o']
                         and Path(argv[17]).name == 'program.so' and Path(argv[14]).parent == Path(argv[17]).parent
                         and Path(argv[14]).parent.parent == out and invocation['wall_limit_seconds'] == 30
                         and invocation['environment'] is None and invocation['pass_fds'] == [] and incoming == b'',
                         'native emitter linker arguments changed')
            if symbol:
                expected_stages.append(('rename-' + name, [tools['objcopy']['path'], '--redefine-sym', 'f0=' + symbol,
                    out / (name + '.o'), out / (name + '-private.o')], b''))
    finally:
        toolchain.LOCK = saved_lock
    need(same(native_calls, value['native_invocations']), 'duplicate or reordered native invocation')
    request = {'image': str(out / 'owned-emitter.so'), 'sha256': sha(read(directory, 'owned-emitter.so')), 'output': str(out / 'owned.o')}
    expected_stages += [
        ('emit-owned', [python, '-I', '-S', '-B', executed_repo / (PREFIX + 'emit_owned.py')], json.dumps(request).encode()),
        ('inspect-owned', [tools['objdump']['path'], '-dr', out / 'owned.o'], b''),
        ('link-owned', [tools['ld']['path'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro',
            '-z', 'now', '--build-id=none', '--hash-style=both', '--version-script=' + str(executed_repo / (PREFIX + 'owned.map')),
            out / 'owned.o', out / 'auth-private.o', out / 'verify-private.o', out / 'profile-private.o', '-lc', '-o', out / 'pq-owned.so'], b''),
        ('public-symbols', [tools['nm']['path'], '-D', '--defined-only', out / 'pq-owned.so'], b''),
    ]
    need(len(value['stages']) == len(expected_stages), 'native build stage count changed')
    for row, (name, argv, incoming) in zip(value['stages'], expected_stages):
        # These builder subprocesses remain inside the actual native-build
        # parent's 240-second group; the outer stage owns its bounded cleanup.
        stage(directory, row, name, argv, executed_repo, 60, incoming, supervised=False)
    emitted = document(read(directory, 'emit-owned.stdout.raw'))
    need(emitted['status'] == 'PASS' and emitted['host_compiler_modules_loaded'] == []
         and emitted['image_sha256'] == request['sha256'] and emitted['object_sha256'] == sha(read(directory, 'owned.o'))
         and emitted['object_bytes'] == len(read(directory, 'owned.o')), 'owned object did not match actual HIA emission')
    expected_exports = document(read(source_root, PREFIX + 'owned_exports.json'))['exports']
    actual = sorted(line.split()[-1] for line in read(directory, 'public-symbols.stdout.raw').decode().splitlines())
    need(len(expected_exports) == 55 and len(set(expected_exports)) == 55
         and actual == sorted(expected_exports) == value['exports'], 'public symbol surface differs')
    for name, expected in value['artifacts'].items():
        bound(directory, name, expected)
    need(value['final_image'] == value['artifacts']['pq-owned.so'] and value['emitted_object'] == value['artifacts']['owned.o'],
         'final native artifact identity differs')
    return value


def validate_cases(root, source_root, image_sha):
    packed = read(source_root, PREFIX + 'qualification/cases.json.xz')
    corpus = document(lzma.decompress(packed))
    need(len(corpus) == 1609 and len({row['label'] for row in corpus}) == 1609
         and Counter(row['family'] for row in corpus) == {'auth': 578, 'profile': 1031}
         and Counter(row['suite'] for row in corpus) == {'methods': 1480, 'extended': 129}, 'case roster changed')
    all_rows, total, functions = [], 0, Counter()
    for name, suite, begin, end in PARTITIONS:
        count = end - begin
        value = document(read(root, name + '/report.json'))
        need(value['status'] == 'PASS' and value['image_sha256'] == image_sha and value['corpus'] == suite
             and value['partition'] == name
             and value['method_cases'] == count and value['live_values'] == 0
             and value['fresh_original_process_executed'] is False, 'native case corpus incomplete')
        expected = partition_cases(corpus, name)
        actual = document(lzma.decompress(read(root, name + '/cases.json.xz')))
        need(same(actual, expected), 'native case omitted, duplicated or changed')
        need(read(root, name + '/fixture.py') == read(source_root, PREFIX + 'qualification/native_cases.py')
             and read(root, name + '/supplied-cases.json.xz') == packed, 'native case source differs')
        calls, seen, labels = Counter(), [], {row['label'] for row in expected}
        with gzip.GzipFile(fileobj=io.BytesIO(read(root, name + '/native-calls.jsonl.gz'))) as stream:
            for raw in stream:
                row = document(raw)
                need(row['case'] in labels and row['function'] in value['functions'], 'unbound native ABI observation')
                calls[row['function']] += 1
                if not seen or seen[-1] != row['case']:
                    seen.append(row['case'])
                if 'status' in row:
                    need(row['status'] == 0 and row['has_value'] is True, 'unexpected ABI allocation failure')
                if 'size' in row and row['value'] is not None:
                    need(len(bytes.fromhex(row['value'])) == row['size'], 'truncated borrowed-value observation')
        need(seen == [row['label'] for row in expected] and same(dict(calls), value['functions'])
             and sum(calls.values()) == value['native_calls'], 'native ABI calls were omitted')
        all_rows += actual
        total += value['native_calls']
        functions += calls
    need(total == 24671 and len(functions) == 55, 'public ABI surface was not exercised exactly')
    return all_rows, total


def validate_supervision_controls(root, source_root, repository, output, python):
    from hia.platform.pq_auth.qualification.supervision_controls import NAMES, specs
    directory = root / 'supervision-controls'
    value = document(read(directory, 'report.json'))
    need(value.get('status') == 'PASS' and value.get('scope') == 'short-real-deadlines-not-the-separate-240-second-demonstration'
         and value['python'] == python and value['cwd'] == str(repository)
         and [row['name'] for row in value['cases']] == list(NAMES), 'supervision control roster incomplete')
    need(read(directory, 'fixture.py') == read(source_root, PREFIX + 'qualification/supervision_controls.py')
         and read(directory, 'supervision.py') == read(source_root, PREFIX + 'qualification/supervision.py'),
         'supervision controls used different code')
    need(same(value.get('reaper_deadline_control'), {'status': 'PASS',
         'scope': 'injected-clock-and-waitpid-algorithm-only', 'absolute_deadline': 101.0,
         'clock_readings': [100.0, 100.5, 101.0], 'waitpid_calls': [[-777, 1], [-777, 1]],
         'actual_process_cleanup_claimed': False}), 'reaper deadline boundary control omitted or promoted')
    expected_outcomes = ('success', 'exit-nonzero', 'timeout', 'timeout', 'descendants-outlived-leader',
                         'timeout', 'cleanup-incomplete', 'launch-error')
    for row, spec, outcome in zip(value['cases'], specs(output / 'supervision-controls', python), expected_outcomes):
        name, receipt = row['name'], row['receipt']
        process_receipt(receipt, spec['argv'], repository, spec['limit'], success=name == 'normal')
        need(receipt['outcome'] == outcome and same(receipt, document(read(directory, name + '.receipt.json'))),
             'supervision control outcome or raw receipt differs')
        for stream in ('stdin', 'stdout', 'stderr'):
            bound(directory, name + '.' + stream + '.raw', row[stream])
        need(read(directory, name + '.stdin.raw') == spec['data'], 'supervision control input differs')
        if name == 'normal':
            need(read(directory, name + '.stdout.raw') == spec['data']
                 and read(directory, name + '.stderr.raw') == b'normal-stderr\x00\n', 'supervision streams were truncated')
        if name == 'nonzero':
            need(receipt['exit_code'] == 7 and receipt['timed_out'] is False
                 and read(directory, name + '.stdout.raw') == b'nonzero-stdout\n'
                 and read(directory, name + '.stderr.raw') == b'nonzero-stderr\n', 'nonzero process was promoted')
        if name not in ('cleanup-denied', 'launch-error'):
            need(receipt['cleanup_complete'] is True and receipt['direct_child_reaped'] is True
                 and receipt['group_absent'] is True and receipt['streams_complete'] is True
                 and receipt['cleanup_seconds'] <= 3, 'actual control cleanup incomplete')
        if name in ('native-timeout', 'group-timeout', 'held-pipe-timeout', 'cleanup-denied'):
            need(receipt['timed_out'] is True and spec['limit'] <= receipt['execution_seconds'] < spec['limit'] + 1,
                 'real execution timeout was not observed')
        if name in ('native-timeout', 'group-timeout', 'orphan-after-exit', 'held-pipe-timeout', 'cleanup-denied'):
            announced = document(read(directory, name + '.stdout.raw'))
            need(announced['leader'] == receipt['pid'] and len(receipt['killpg_attempts']) == 1,
                 'process-group control did not kill its actual child')
            need(read(directory, name + '.stderr.raw') == b'before-native-pause\n', 'native pause fixture did not run')
            if name != 'cleanup-denied':
                need(receipt['killpg_attempts'][0]['errno'] == 0, 'actual process-group kill failed')
            if name in ('group-timeout', 'orphan-after-exit', 'held-pipe-timeout'):
                need(receipt['adopted_reaped'] == [{'pid': announced['grandchild'], 'wait_status': 9, 'exit_code': -9}],
                     'actual adopted grandchild was not reaped')
            if name == 'orphan-after-exit':
                need(receipt['exit_code'] == 0 and receipt['timed_out'] is False
                     and receipt['descendants_outlived_leader'] is True, 'orphan process was promoted')
            if name == 'cleanup-denied':
                need(row['injection'] == [{'pgid': receipt['pgid'], 'signal': 9, 'errno': 1}]
                     and receipt['killpg_attempts'][0]['errno'] == 1 and receipt['cleanup_complete'] is False
                     and receipt['group_absent'] is False and 3 <= receipt['cleanup_seconds'] < 3.5,
                     'injected kill denial was promoted to actual cleanup')
                cleanup = row['fixture_teardown']
                need(cleanup['status'] == 'REMOVED_INJECTED_FIXTURE' and cleanup['group_absent'] is True
                     and 0 <= cleanup['seconds'] <= 3 and cleanup['reaped'] ==
                     [{'pid': receipt['pid'], 'wait_status': 9, 'exit_code': -9}], 'denial fixture left a process behind')
        if name != 'cleanup-denied':
            need(row['injection'] == [], 'unexpected injected process result')
        if name == 'launch-error':
            need(receipt['pid'] is None and receipt['launch_error']['errno'] == 2
                 and receipt['killpg_attempts'] == [] and receipt['cleanup_complete'] is False,
                 'launch error was promoted to process success')
    return len(NAMES)


def validate_ownership(root, source_root, image_sha, observer_sha):
    allocation = document(read(root, 'allocations/report.json'))
    rows = document(read(root, 'allocations/controls.json'))
    need(allocation.get('status') == 'PASS' and allocation['image_sha256'] == observer_sha
         and allocation['controls'] == 190 and allocation['failure_controls'] == 125 and allocation['live_values'] == 0
         and allocation['heap_allocation_wipe_scope_only'] is True
         and allocation['secret_register_stack_or_constant_time_qualified'] is False
         and len(rows) == 190 and len(allocation['operations']) == 32, 'incomplete allocation controls')
    need(read(root, 'allocations/fixture.py') == read(source_root, PREFIX + 'qualification/allocations.py'), 'allocation fixture changed')
    baseline = [2, 2, 0, 0, 0, 0, 1, 32, 32]
    need(allocation['allocator_observer_baseline'] == baseline
         and allocation['observer_positive_controls'] == {'clean_probe_bytes': 32, 'unwiped_detected_bytes': 32},
         'allocator observer positive controls missing')
    position, failures = 0, 0
    for operation in allocation['operations']:
        count = 1 if operation['name'] == 'seed-copy' else 4
        need(operation['allocation_positions'] == count, 'allocation position roster altered')
        for fail_at in [0, *range(1, count + 1), 0]:
            row = rows[position]
            position += 1
            need(row['operation'] == operation['name'] and row['entry'] == operation['entry'] and row['fail_at'] == fail_at
                 and row['observed_allocations'] == count and row['result_status'] == (103 if fail_at else 0), 'allocation failure position omitted')
            before, after, cleaned = row['before'], row['after_operation'], row['after_cleanup']
            need(all(len(item) == 9 for item in (before, after, cleaned)) and cleaned[5:8] == baseline[5:8]
                 and after[5:8] == baseline[5:8] and cleaned[2] == 6 and cleaned[3] == 459024,
                 'runtime freed an unwiped or unknown allocation')
            need(after[4] - before[4] == bool(fail_at), 'allocation denial did not occur')
            failures += bool(fail_at)
    null = rows[-1]
    need(position == 189 and failures == 125 and null['operation'] == 'null-pin-consumes-seed'
         and null['entry'] == 'signing_from_owned_seed' and null['result_status'] == 104 and null['has_value'] is False
         and null['before'][0] == null['after_cleanup'][0]
         and null['before'][2] == null['after_cleanup'][2] + 1, 'owned seed failure was not consumed')
    need(allocation['final_stats'] == [695, 570, 0, 0, 125, 0, 1, 32, 46413396], 'allocation/final wipe accounting differs')
    lifetime = document(read(root, 'lifetimes/report.json'))
    calls = document(read(root, 'lifetimes/calls.json'))
    need(lifetime['status'] == 'PASS' and lifetime['image_sha256'] == image_sha and lifetime['abi_calls'] == len(calls) == 1329
         and lifetime['abi_refusals'] == 25 and lifetime['independent_post_owner_values'] == 198
         and lifetime['readonly_owner_shared_threads'] == 8 and lifetime['owned_values_remaining'] == 0
         and lifetime['caller_live_pointer_and_const_contract_required'] is True
         and lifetime['arbitrary_foreign_pointer_gate_qualified'] is False
         and lifetime['concurrent_mutation_of_same_budget_supported'] is False and lifetime['constant_time_qualified'] is False,
         'lifetime or ABI controls incomplete')
    need(read(root, 'lifetimes/fixture.py') == read(source_root, PREFIX + 'qualification/lifetimes.py'), 'lifetime fixture changed')
    threads = lifetime['threads']
    need(len(threads) == 8 and {row['index'] for row in threads} == set(range(8))
         and len({row['thread'] for row in threads}) == 8, 'real parallel owner readers missing')
    events = []
    for row in calls:
        need(row['seconds'] >= 0 and row['started'] > 0, 'invalid lifetime timing')
        if 'data_hex' in row:
            need((row['data_hex'] is None and not row['has_data']) or
                 (row['has_data'] is True and len(bytes.fromhex(row['data_hex'])) == row['size']), 'lifetime view bytes truncated')
        if row['name'] in ('sign_exact_message', 'verify_exact_message', 'profile_verify'):
            events += [(row['started'], 1), (row['started'] + row['seconds'], -1)]
    active, peak = 0, 0
    for _, change in sorted(events, key=lambda pair: (pair[0], -pair[1])):
        active += change
        peak = max(peak, active)
    need(active == 0 and 2 <= peak <= 8 and peak >= lifetime['maximum_concurrent_primary_calls'] >= 2,
         'concurrent read calls were not actually observed')
    return allocation, lifetime


def validate_evidence(root, source_root=ROOT, expected_source_sha256=None):
    root, source_root = regular(root, directory=True), regular(source_root, directory=True)
    value = document(read(root, 'report.json'))
    need(value.get('schema') == SCHEMA and value.get('status') in ('EXECUTED', 'PASS') and same(value.get('limits'), LIMITS),
         'incomplete or promoted qualification')
    sources = input_map(source_root, git_original=expected_source_sha256 is None)
    digest = sha(canonical(sources))
    need((expected_source_sha256 is None or digest == expected_source_sha256)
         and value.get('source_set_sha256') == digest and same(value.get('source_inputs'), sources)
         and value.get('source_unchanged_during_tests') is True, 'changed source graph')
    need(same(value.get('environment_guard'), ml_dsa_original.ENVIRONMENT_GUARD), 'environment guard omitted')
    need(same(value.get('platform_environment_guard'), PLATFORM_GUARD), 'platform environment guard omitted')
    for name, expected in sources.items():
        need(sha(read(root, 'inputs/' + name)) == expected, 'retained source changed')
    repository, out = Path(value['repository']), Path(value['output'])
    need(repository.is_absolute() and out.is_absolute(), 'unbound execution location')
    python, rust = value['python'], Path(value['rust_bin'])
    need(Path(python).is_absolute() and rust.is_absolute(), 'unbound compiler or runner path')
    supervision_controls = validate_supervision_controls(root, source_root, repository, out, python)
    build = validate_native_build(root, source_root, sources, repository, out, python)
    production = value['production_image']
    need(production['retained'] == 'native/pq-owned.so' and production['path'] == str(out / production['retained'])
         and {key: production[key] for key in ('bytes', 'sha256')} == build['final_image'], 'public image binding differs')
    bound(root, production['retained'], production)
    rows, native_calls = validate_cases(root, source_root, production['sha256'])
    observer = value['observer_image']
    need(observer['retained'] == 'observer/pq-owned-observed.so', 'wrong observed image')
    bound(root, observer['retained'], observer)
    allocation, lifetime = validate_ownership(root, source_root, production['sha256'], observer['sha256'])
    objects = ('owned.o', 'auth-private.o', 'verify-private.o', 'profile-private.o')
    need(value['observer_production_objects'] == {name: build['artifacts'][name] for name in objects}, 'observer changed production objects')
    expected_map = read(source_root, PREFIX + 'owned.map').decode().replace('  global:\n',
        '  global:\n    trnm_pq_test_stat;\n    trnm_pq_test_fail_after;\n    trnm_pq_test_probe;\n')
    need(read(root, 'observer/observer.map') == expected_map.encode(), 'observer export policy changed')
    symbols = sorted(line.split()[-1] for line in read(root, 'observer-symbols.stdout.raw').decode().splitlines())
    need(symbols == sorted([*build['exports'], 'trnm_pq_test_stat', 'trnm_pq_test_fail_after', 'trnm_pq_test_probe']), 'observer symbols differ')
    original = document(read(root, 'original/report.json'))
    need(sha(read(root, 'original/report.json')) == value['original_report_sha256']
         and original['head'] == value['source_commit_observed'] and original['tree'] == value['source_tree_observed'], 'original lineage/report mismatch')
    provider = document(read(root, 'provider.json'))
    with original_source(source_root):
        qualify_ml_dsa.validate_provider(provider, retained=root)
        qualify_ml_dsa.provider_environment(provider, original['environment'])
        qualify_ml_dsa.validate_original(original, root / 'original', sources)
    need(value['provider_inputs_unchanged_after_original'] is True and value['provider_inputs_unchanged_after_adapter_links'] is True,
         'actual live provider was not checked after linkage')
    environment = dict(line.split('=', 1) for line in read(root, 'provider.env').decode().splitlines())
    need(len(read(root, 'provider.env').decode().splitlines()) == len(environment) == 7,
         'duplicate or omitted provider environment field')
    qualify_ml_dsa.provider_environment(provider, environment)
    artifacts = document(read(root, 'original/artifacts.json'))
    graph = value['adapter_graph']
    need(set(graph) == set(LIBRARIES), 'original direct dependency graph omitted')
    for name, row in graph.items():
        events = [event for event in artifacts if event['target']['name'] == name and row['path'] in event['filenames']]
        need(len(events) == 1 and row['package_id'] == events[0]['package_id'] and row['features'] == events[0]['features']
             and row['retained'] == 'adapters/dependencies/' + Path(row['path']).name, 'adapter detached from actual Cargo graph')
        bound(root, row['retained'], row)
    need(set(value['original_adapters']) == set(ADAPTERS), 'original adapter omitted')
    tools = value['tools']
    need(set(tools) == {'cc', 'ld', 'nm'}, 'platform tool binding omitted')
    for row in tools.values():
        need(Path(row['path']).is_absolute() and row['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'bad platform tool identity')
    expected = [('git-head', ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], 180, b''),
        ('git-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all'], 180, b''),
        ('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'], 180, b''),
        ('supervision-controls', [python, '-I', '-S', '-B', repository / (PREFIX + 'qualification/supervision_controls.py'),
            '--output', out / 'supervision-controls'], 30, b''),
        ('original-complete', [python, '-I', '-S', '-B', repository / 'hia/tools/ml_dsa_original.py', '--repository', repository,
            '--output', out / 'original', '--rust-bin', rust, '--provider-environment', out / 'provider.env'], 1200, b'')]
    for family, source in ADAPTERS.items():
        adapter = value['original_adapters'][family]
        need(adapter['source'] == source and adapter['source_sha256'] == sources[source]
             and adapter['retained'] == 'adapters/' + family + '-reference'
             and adapter['path'] == str(out / adapter['retained']), 'wrong original adapter identity')
        bound(root, adapter['retained'], adapter)
        expected += [('format-' + family, [rust / 'rustfmt', '--edition', '2021', '--check', repository / source], 180, b''),
            ('build-' + family, adapter_command(rust, repository, out / 'original', provider['install_prefix'], graph, family, adapter['path']), 180, b'')]
    expected.append(('native-build', [python, '-I', '-S', '-B', repository / (PREFIX + 'build_owned.py'), '--output', out / 'native'], 240, b''))
    image = out / 'native/pq-owned.so'
    for partition, _, _, _ in PARTITIONS:
        expected.append(('native-' + partition, [python, '-I', '-S', '-B', repository / (PREFIX + 'qualification/native_cases.py'),
            '--image', image, '--image-sha256', production['sha256'], '--partition', partition,
            '--output', out / partition], 240, b''))
    for family in ADAPTERS:
        cases = [row for row in rows if row['family'] == family]
        incoming = b''.join((json.dumps(row['original'], sort_keys=True) + '\n').encode() for row in cases)
        expected.append(('compare-' + family, [value['original_adapters'][family]['path']], 240, incoming))
        actual = [document(line) for line in read(root, 'compare-' + family + '.stdout.raw').splitlines()]
        need(len(actual) == len(cases) and read(root, 'compare-' + family + '.stderr.raw') == b'', 'partial original comparison')
        need(all(same(normalize(family, observed), case['native']) for observed, case in zip(actual, cases)), 'actual original/native observations differ')
    source = repository / PREFIX
    observed = out / 'observer/pq-owned-observed.so'
    expected += [
        ('observer-compile', [tools['cc']['path'], '-std=c11', '-O2', '-fPIC', '-Wall', '-Wextra', '-Werror', '-c', source / 'qualification/allocator_observer.c', '-o', out / 'observer/observer.o'], 180, b''),
        ('observer-link', [tools['ld']['path'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro', '-z', 'now',
            '--build-id=none', '--hash-style=both', '--wrap=calloc', '--wrap=free', '--version-script=' + str(out / 'observer/observer.map'),
            out / 'observer/observer.o', *[out / 'native' / name for name in objects], '-lc', '-lpthread', '-o', observed], 180, b''),
        ('observer-symbols', [tools['nm']['path'], '-D', '--defined-only', observed], 180, b''),
        ('allocations', [python, '-I', '-S', '-B', source / 'qualification/allocations.py', '--image', observed, '--image-sha256', observer['sha256'], '--output', out / 'allocations'], 180, b''),
        ('lifetimes', [python, '-I', '-S', '-B', source / 'qualification/lifetimes.py', '--image', image, '--image-sha256', production['sha256'], '--output', out / 'lifetimes'], 180, b''),
        ('header-compile', [tools['cc']['path'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', source,
            source / 'qualification/abi_client.c', image, '-Wl,-rpath,' + str(image.parent), '-o', out / 'header-client'], 180, b''),
        ('header-client', [out / 'header-client'], 180, b''),
    ]
    need(len(value['stages']) == len(expected), 'qualification stage omitted')
    for row, (name, argv, limit, incoming) in zip(value['stages'], expected):
        stage(root, row, name, argv, repository, limit, incoming)
    need(read(root, 'git-head.stdout.raw').decode().splitlines() == [value['source_commit_observed'], value['source_tree_observed']]
         and read(root, 'git-status.stdout.raw').decode() == value['source_dirty_observed'], 'lineage observation changed')
    need(document(read(root, 'header-client.stdout.raw')) == {'status': 'PASS', 'public_header_consumer': True}, 'public C header consumer failed')
    need(value['native_original_pairs'] == 1609, 'original comparison count differs')
    files = value['files']
    need(type(files) is dict and files and 'report.json' not in files, 'missing artifact inventory')
    actual_files = set()
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        if name == 'report.json' or name.startswith('original/target/'):
            continue
        need(not path.is_symlink(), 'symlinked artifact inventory')
        if path.is_file():
            actual_files.add(name)
    need(set(files) == actual_files, 'artifact inventory omitted or invented files')
    for name, expected_file in files.items():
        need(not relative(name).startswith('original/target/'), 'unretained intermediate target in public evidence')
        bound(root, name, expected_file)
    return {'status': 'PASS', 'source_files': len(sources), 'source_set_sha256': digest,
            'source_commit_observed': value['source_commit_observed'], 'source_tree_observed': value['source_tree_observed'],
            'source_dirty_observed': value['source_dirty_observed'], 'native_original_pairs': 1609,
            'native_abi_calls': native_calls, 'exports': len(build['exports']), 'production_image': production,
            'allocation_controls': allocation['controls'], 'actual_allocation_failures': allocation['failure_controls'],
            'lifetime_abi_calls': lifetime['abi_calls'], 'parallel_readers': 8,
            'real_process_controls': supervision_controls, 'native_partitions': len(PARTITIONS),
            'native_execution_limit_seconds': 240, 'single_cleanup_limit_seconds': 3,
            'original_retained': 343, 'original_doctests': 2, 'files_read': len(files), 'limits': LIMITS}


def validate(root, source_root=ROOT, expected_source_sha256=None):
    value = document(read(root, 'report.json'))
    need(value.get('status') == 'PASS', 'qualification is partial or failed')
    from hia.platform.pq_auth.qualification.integrity import NAMES
    controls = document(read(root, 'integrity.json'))
    need(controls.get('status') == 'PASS' and controls.get('run') == len(NAMES)
         and [row['name'] for row in controls['cases']] == list(NAMES)
         and all(row.get('status') == 'REJECTED' and row.get('error') for row in controls['cases']), 'reader integrity controls incomplete')
    executed_raw = read(root, 'executed-report.json')
    executed = document(executed_raw)
    need(executed['status'] == 'EXECUTED' and controls.get('baseline_report_sha256') == sha(executed_raw)
         and controls.get('source_set_sha256') == value['source_set_sha256']
         and controls.get('fixture_sha256') == value['source_inputs'].get(PREFIX + 'qualification/integrity.py'),
         'reader controls belong to different evidence')
    need(same({key: item for key, item in executed.items() if key not in ('status', 'files', 'seconds')},
              {key: item for key, item in value.items() if key not in ('status', 'files', 'seconds')})
         and set(value['files']) == set(executed['files']) | {'executed-report.json', 'integrity.json'}
         and all(value['files'][name] == row for name, row in executed['files'].items()),
         'final evidence changed after reader controls')
    result = validate_evidence(root, source_root, expected_source_sha256)
    result['reader_integrity_controls'] = len(NAMES)
    result['qualification_report_sha256'] = sha(read(root, 'report.json'))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--source-set-sha256')
    args = parser.parse_args()
    need(not sys.flags.optimize, 'optimized Python is not independent readback')
    print(json.dumps(validate(args.report, args.source_root, args.source_set_sha256), sort_keys=True), flush=True)
