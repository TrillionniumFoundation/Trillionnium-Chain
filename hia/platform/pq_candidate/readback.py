"""Independently read Candidate evidence without executing a tested image."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import argparse
import gzip
import json
import lzma
import math
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_candidate.qualification.contract import (
    COMPILER, COUNTS, LIMITS, METHODS, PARTITION_COUNTS, PLATFORM_GUARD, PREFIX, REVISION, SCHEMA,
    UNITS, canonical, compose, document, identity, input_map, jsonl, need, normalize,
    read, regular, relative, same, sha,
)
from hia.platform.pq_candidate.qualification import cases
from hia.platform.pq_candidate.qualification.api import SIGNATURES
from hia.platform.pq_auth.readback import (
    bound, original_source, process_receipt, stage, validate_supervision_controls,
)
from hia.tools import ml_dsa_original, qualify_ml_dsa, toolchain


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
    need(len(value['builds']) == 3, 'native image roster omitted')
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
            out / 'owned.o', out / 'candidate-private.o', out / 'gate-private.o', '-lc', '-o', out / 'candidate-owned.so'], b''),
        ('public-symbols', [tools['nm']['path'], '-D', '--defined-only', out / 'candidate-owned.so'], b''),
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
    need(len(expected_exports) == 25 and len(set(expected_exports)) == 25
         and actual == sorted(expected_exports) == value['exports'], 'public symbol surface differs')
    for name, expected in value['artifacts'].items():
        bound(directory, name, expected)
    need(value['final_image'] == value['artifacts']['candidate-owned.so'] and value['emitted_object'] == value['artifacts']['owned.o'],
         'final native artifact identity differs')
    return value


def validate_cases(root, source_root, image_sha):
    initial = cases.fixture_requests()
    first_values = [document(line) for line in read(root, 'fixtures-original.stdout.raw').splitlines()]
    first = cases.fixture_map(initial, first_values)
    modes = cases.mode_requests(first)
    mode_values = [document(line) for line in read(root, 'modes-original.stdout.raw').splitlines()]
    second = cases.fixture_map(modes, mode_values)
    validation = [document(line) for line in read(root, 'mode-validity-original.stdout.raw').splitlines()]
    need(len(validation) == len(modes) == 12 and all(row == {'code': 0, 'expected': 0, 'actual': 0}
         for row in validation), 'mode-separation fixtures were not accepted under their actual modes')
    rows = cases.corpus(first_values, mode_values)
    need(same(document(lzma.decompress(read(root, 'cases.json.xz'))), rows)
         and len(rows) == COUNTS['native_cases'] and Counter(row['partition'] for row in rows) == PARTITION_COUNTS,
         'deterministic native roster differs')
    originals = [document(line) for line in read(root, 'comparison-original.stdout.raw').splitlines()]
    need(len(originals) == len(rows), 'original comparison returned a partial roster')
    original_map = {row['label']: normalize(row['original'], value) for row, value in zip(rows, originals)}
    total, functions = 0, Counter()
    for partition, count in PARTITION_COUNTS.items():
        value = document(read(root, partition + '/report.json'))
        need(value.get('status') == 'PASS' and value['image_sha256'] == image_sha and value['partition'] == partition
             and value['cases'] == count and value['remaining_live_owners'] == 0
             and value['fresh_original_process_executed'] is False, 'incomplete native partition')
        wanted = cases.selected(rows, partition)
        observations = [document(line) for line in gzip.decompress(read(root,
            partition + '/native-values.jsonl.gz')).splitlines()]
        need([row['label'] for row in observations] == [row['label'] for row in wanted],
             'native case omitted, duplicated or reordered')
        for row in observations:
            need(row['result'] == original_map[row['label']], 'native observation differs from actual original: ' + row['label'])
        calls, seen, sequence = Counter(), [], 0
        labels = {row['label'] for row in wanted}
        for raw in gzip.decompress(read(root, partition + '/native-calls.jsonl.gz')).splitlines():
            row = document(raw)
            sequence += 1
            need(row['sequence'] == sequence and row['case'] in labels and row['function'] in SIGNATURES,
                 'unbound native ABI call')
            calls[row['function']] += 1
            if not seen or seen[-1] != row['case']:
                seen.append(row['case'])
            if 'status' in row:
                need(row['status'] == 0 and row.get('has_value', True) is True, 'native ABI failed')
            if 'size' in row:
                need(row['has_data'] is True and type(row['size']) is int and row['size'] >= 0
                     and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'invalid native view observation')
        need(seen == [row['label'] for row in wanted] and same(dict(calls), value['function_counts'])
             and sequence == value['native_calls'], 'native ABI calls omitted or reordered')
        total += sequence
        functions += calls
    need(total == COUNTS['native_abi_calls'] and set(functions) == set(SIGNATURES), 'complete public ABI surface missing')
    return rows, first, total, initial, modes, cases.mode_validation_requests(first, modes, second)


def allocation_roster():
    rows = [('seed-copy', 'seed_copy', 1), ('all', 'algorithm_all', 4)]
    for algorithm in (65, 87):
        for suffix, entry, count in (
                ('owned-seed', 'signing_from_owned_seed', 4), ('verifier', 'verifier_from_pinned_raw', 4),
                ('sign', 'sign', 4), ('verify', 'verify', 4), ('name', 'algorithm_name', 4),
                ('error-value', 'error_display', 4), ('error-enum', 'candidate_error_display', 4),
                ('public-length', 'verifier_from_pinned_raw', 1), ('sign-length', 'sign', 1),
                ('verify-length', 'verify', 1), ('signature-length', 'verify', 1),
                ('encoding', 'verify', 4), ('challenge', 'verify', 4),
                ('algorithm_public_key_bytes', 'algorithm_public_key_bytes', 4),
                ('algorithm_signature_bytes', 'algorithm_signature_bytes', 4),
                ('algorithm_nist_category', 'algorithm_nist_category', 4)):
            rows.append((f'{algorithm}-{suffix}', entry, count))
    return rows


def validate_ownership(root, source_root, image_sha, observer_sha, fixtures):
    allocation = document(read(root, 'allocations/report.json'))
    rows = document(read(root, 'allocations/controls.json'))
    need(allocation.get('status') == 'PASS' and allocation['image_sha256'] == observer_sha
         and allocation['controls'] == len(rows) == COUNTS['allocation_controls']
         and allocation['failure_controls'] == COUNTS['actual_allocation_failures'] and allocation['live_values'] == 0
         and allocation['heap_allocation_wipe_scope_only'] is True
         and allocation['constant_time_qualified'] is False and allocation['secret_register_or_stack_erasure_qualified'] is False,
         'incomplete allocation controls')
    baseline = [2, 2, 0, 0, 0, 0, 1, 32, 32]
    need(allocation['allocator_observer_baseline'] == baseline and allocation['observer_positive_controls'] ==
         {'clean_probe_bytes': 32, 'unwiped_detected_bytes': 32}, 'allocator observer positive controls missing')
    roster = allocation_roster()
    need(allocation['operations'] == [{'name': name, 'entry': entry, 'allocation_positions': count}
         for name, entry, count in roster], 'allocation operation roster differs')
    position, failures, previous = 0, 0, None
    for operation, entry, count in roster:
        for fail_at in [0, *range(1, count + 1), 0]:
            row = rows[position]
            position += 1
            need(row['operation'] == operation and row['entry'] == entry and row['fail_at'] == fail_at
                 and row['observed_allocations'] == count and row['result_status'] == (103 if fail_at else 0),
                 'allocation failure position omitted')
            before, after, cleaned = row['before'], row['after_operation'], row['after_cleanup']
            need(all(type(item) is list and len(item) == 9 and all(type(x) is int and x >= 0 for x in item)
                 for item in (before, after, cleaned)), 'invalid allocator counters')
            need(cleaned[2] == 6 and after[5:8] == cleaned[5:8] == baseline[5:8],
                 'runtime freed an unwiped or unknown allocation')
            need(after[0] - before[0] == (fail_at or count) and after[4] - before[4] == bool(fail_at)
                 and cleaned[0] == after[0] and cleaned[4] == after[4], 'actual allocation denial differs')
            need(cleaned[0] == cleaned[1] + cleaned[2] + cleaned[4], 'allocation/free accounting differs')
            if previous is not None:
                extra = 1 if entry == 'signing_from_owned_seed' else 0
                need(before[0] == previous[0] + extra and before[1] == previous[1]
                     and before[4] == previous[4], 'allocation sequence was reset or omitted')
            previous = cleaned
            failures += bool(fail_at)
    for algorithm in (0, 1, 64, 66, 86, 88, 255, 256, (1 << 64) - 1):
        row = rows[position]
        position += 1
        before, after = row['before'], row['after_cleanup']
        need(row['operation'] == 'invalid-algorithm-consumes-seed' and row['algorithm'] == algorithm
             and row['result_status'] == 104 and before[0] == previous[0] + 1
             and before[1] == previous[1] and before[4] == previous[4]
             and after[0] == before[0] and after[1] == before[1] + 1
             and before[2] == after[2] + 1 and after[2] == 6 and after[5:8] == baseline[5:8],
             'invalid-parameter seed was not consumed and wiped')
        previous = after
    need(position == len(rows) and failures == COUNTS['actual_allocation_failures'], 'allocation controls incomplete')
    final = allocation['final_stats']
    need(final[0] == previous[0] and final[1] == previous[1] + 6 and final[2:4] == [0, 0]
         and final[4] == failures and final[5:8] == baseline[5:8]
         and final[0] == final[1] + final[4] and final[8] > previous[8], 'final allocation/wipe accounting differs')
    lifetime = document(read(root, 'lifetimes/report.json'))
    calls = document(read(root, 'lifetimes/calls.json'))
    need(lifetime['status'] == 'PASS' and lifetime['image_sha256'] == image_sha
         and lifetime['abi_calls'] == len(calls) == COUNTS['lifetime_abi_calls'] and lifetime['abi_refusals'] == 70
         and lifetime['independent_post_owner_values'] == COUNTS['independent_post_owner_values']
         and lifetime['readonly_owner_shared_threads'] == COUNTS['readonly_owner_shared_threads']
         and lifetime['owned_values_remaining'] == 0 and lifetime['caller_live_pointer_and_const_contract_required'] is True
         and lifetime['arbitrary_foreign_pointer_gate_qualified'] is False and lifetime['constant_time_qualified'] is False,
         'lifetime or ABI control roster incomplete')
    threads = lifetime['threads']
    need(len(threads) == 8 and {row['index'] for row in threads} == set(range(8))
         and len({row['thread'] for row in threads}) == 8, 'real parallel owner readers missing')
    expected_views, aliases = {}, []
    for parameter in (65, 87):
        public = fixtures[f'key-{parameter}-2']['pk']
        signature = fixtures[f'sign-{parameter}-1']['signature']
        alias = document(read(root, f'lifetimes/alias-original-{parameter}.json'))
        need(alias['label'] == f'const-public-key-as-message-{parameter}' and alias['original'] == {
            'op': 'sign', 'parameter': parameter, 'seed': cases.SEEDS[2].hex(), 'message': public},
            'borrowed-public-key alias fixture differs')
        aliases.append(alias)
        for name, encoded in (('signing_public_key', public), ('verifier_public_key', public),
                              ('signature_bytes', signature), ('signature_bytes', alias['native']['signature'])):
            raw = bytes.fromhex(encoded)
            expected_views.setdefault(name, set()).add((len(raw), sha(raw)))
    functions, events, refusals = Counter(), {65: [], 87: []}, 0
    worker_ids = {thread['thread'] for thread in threads}
    for index, row in enumerate(calls, 1):
        need(row['sequence'] == index and row['name'] in SIGNATURES, 'lifetime ABI call omitted')
        need(all(type(row.get(name)) in (int, float) and math.isfinite(row[name]) and row[name] >= 0
             for name in ('started', 'seconds')), 'invalid lifetime timing')
        functions[row['name']] += 1
        if row.get('status') == 104:
            refusals += 1
            need(row.get('has_value', False) is False and row.get('value', 0) == 0, 'ABI refusal returned a value')
        elif 'status' in row:
            need(row['status'] == 0 and row.get('has_value', True) is True, 'unexpected lifetime call failure')
        if 'size' in row:
            need((row['has_data'] is False and row['size'] == 0 and row['sha256'] == sha(b''))
                 or (row['has_data'] is True and (row['size'], row['sha256']) in expected_views.get(row['name'], set())),
                 'lifetime borrowed view was truncated or changed')
        if row['name'] in ('sign', 'verify') and row['thread'] in worker_ids:
            need(row.get('algorithm') in events, 'concurrent call lost its algorithm identity')
            events[row['algorithm']] += [(row['started'], 1), (row['started'] + row['seconds'], -1)]
    need(refusals == 70 and functions['sign'] >= 66 and functions['verify'] >= 66,
         'lifetime public-method calls omitted')
    need(set(lifetime['per_algorithm_maximum_concurrent_calls']) == {'65', '87'}, 'missing shared owner')
    for algorithm, timings in events.items():
        need(len(timings) == 128, 'concurrent method roster omitted')
        active, peak = 0, 0
        for _, change in sorted(timings, key=lambda pair: (pair[0], -pair[1])):
            active += change
            peak = max(peak, active)
        observed = lifetime['per_algorithm_maximum_concurrent_calls'][str(algorithm)]
        need(active == 0 and 2 <= peak <= 8 and type(observed) is int and 2 <= observed <= peak,
             'concurrent read calls were not actually observed')
    return allocation, lifetime, aliases


def validate_evidence(root, source_root=ROOT, expected_source_sha256=None):
    root, source_root = regular(root, directory=True), regular(source_root, directory=True)
    value = document(read(root, 'report.json'))
    need(value.get('schema') == SCHEMA and value.get('status') in ('EXECUTED', 'PASS')
         and same(value.get('limits'), LIMITS) and value.get('full_host_dependency_closure_claimed') is False,
         'incomplete or promoted Candidate qualification')
    sources = input_map(source_root, git_original=expected_source_sha256 is None)
    digest = sha(canonical(sources))
    need((expected_source_sha256 is None or expected_source_sha256 == digest)
         and value.get('source_set_sha256') == digest and same(value.get('source_inputs'), sources)
         and value.get('source_unchanged_during_tests') is True, 'changed source graph')
    for name, expected in sources.items():
        need(sha(read(root, 'inputs/' + name)) == expected, 'retained source changed')
    need(same(value.get('environment_guard'), ml_dsa_original.ENVIRONMENT_GUARD)
         and same(value.get('platform_environment_guard'), PLATFORM_GUARD), 'environment guard omitted')
    need(value.get('original_method_roster') == list(METHODS), 'original public method roster omitted')
    repository, out = Path(value['repository']), Path(value['output'])
    python, rust = value['python'], Path(value['rust_bin'])
    need(all(path.is_absolute() for path in (repository, out, Path(python), rust)), 'unbound execution location')
    tools = value['tools']
    need(set(tools) == {'cc', 'ld', 'nm', 'objcopy', 'objdump', 'python'}, 'host tool roster omitted')
    for name, row in tools.items():
        need(Path(row['path']).is_absolute() and row['retained'] == 'tools/' + name, 'unbound host tool')
        bound(root, row['retained'], row)
    need(tools['python']['path'] == python, 'different qualification interpreter')
    controls = validate_supervision_controls(root, source_root, repository, out, python)
    build = validate_native_build(root, source_root, sources, repository, out, python)
    for name, row in build['platform_tools'].items():
        need({key: tools[name][key] for key in ('path', 'bytes', 'sha256')} == row,
             'native build used different captured platform tool')
    production = value['production_image']
    need(production['retained'] == 'native/candidate-owned.so' and production['path'] == str(out / production['retained'])
         and {key: production[key] for key in ('bytes', 'sha256')} == build['final_image'], 'public image binding differs')
    bound(root, production['retained'], production)
    rows, fixtures, native_calls, initial, modes, mode_validation = validate_cases(root, source_root, production['sha256'])
    need(value.get('case_count') == value.get('native_cases') == len(rows)
         and value.get('case_roster_sha256') == sha(canonical(rows))
         and value.get('original_mode_signatures_accepted_under_their_own_modes') == 12
         and value.get('native_abi_calls') == native_calls, 'native execution summary differs')
    observer = value['observer_image']
    need(observer['retained'] == 'observer/candidate-observed.so', 'wrong allocator-observed image')
    bound(root, observer['retained'], observer)
    allocation, lifetime, aliases = validate_ownership(root, source_root, production['sha256'], observer['sha256'], fixtures)
    objects = ('owned.o', 'candidate-private.o', 'gate-private.o')
    need(value['observer_production_objects'] == {name: build['artifacts'][name] for name in objects},
         'observer changed production objects')
    expected_map = read(source_root, PREFIX + 'owned.map').decode().replace('  global:\n',
        '  global:\n    trnm_pq_test_stat;\n    trnm_pq_test_fail_after;\n    trnm_pq_test_probe;\n')
    need(read(root, 'observer/observer.map') == expected_map.encode(), 'observer export policy changed')
    symbols = sorted(line.split()[-1] for line in read(root, 'observer-symbols.stdout.raw').decode().splitlines())
    need(symbols == sorted([*build['exports'], 'trnm_pq_test_stat', 'trnm_pq_test_fail_after', 'trnm_pq_test_probe']),
         'observer symbols differ')
    original = document(read(root, 'original/report.json'))
    need(sha(read(root, 'original/report.json')) == value['original_report_sha256']
         and original['head'] == value['source_commit_observed'] and original['tree'] == value['source_tree_observed'],
         'original lineage or report mismatch')
    provider = document(read(root, 'provider.json'))
    with original_source(source_root):
        qualify_ml_dsa.validate_provider(provider, retained=root)
        qualify_ml_dsa.provider_environment(provider, original['environment'])
        qualify_ml_dsa.validate_original(original, root / 'original', sources)
    need(value.get('provider_inputs_unchanged_after_original') is True
         and value.get('provider_inputs_unchanged_after_all_execution') is True, 'actual live provider was not rechecked')
    environment = dict(line.split('=', 1) for line in read(root, 'provider.env').decode().splitlines())
    need(len(read(root, 'provider.env').decode().splitlines()) == len(environment) == 7,
         'duplicate or missing provider environment field')
    qualify_ml_dsa.provider_environment(provider, environment)
    reference = value['original_reference']
    need(same(reference, original['reference']) and reference['path'] == str(out / 'original/original-reference')
         and reference['retained'] == 'original-reference' and reference['source'] == 'hia/tests/rust_ml_dsa_reference.rs'
         and reference['source_sha256'] == sources[reference['source']], 'original reference identity differs')
    bound(root / 'original', reference['retained'], reference)
    expected_stages = [
        ('git-head', ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], 180, b''),
        ('git-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all'], 180, b''),
        ('preflight', ml_dsa_original.PREFLIGHT_COMMAND, 180, b''),
        ('supervision-controls', [python, '-I', '-S', '-B', repository / 'hia/platform/pq_auth/qualification/supervision_controls.py',
            '--output', out / 'supervision-controls'], 30, b''),
        ('original-complete', [python, '-I', '-S', '-B', repository / 'hia/tools/ml_dsa_original.py',
            '--repository', repository, '--output', out / 'original', '--rust-bin', rust,
            '--provider-environment', out / 'provider.env'], 1200, b''),
        ('native-build', [python, '-I', '-S', '-B', repository / (PREFIX + 'build_owned.py'),
            '--output', out / 'native'], 240, b''),
        ('fixtures-original', [reference['path']], 240, jsonl([row['request'] for row in initial])),
        ('modes-original', [reference['path']], 240, jsonl([row['request'] for row in modes])),
        ('mode-validity-original', [reference['path']], 240, jsonl(mode_validation)),
        ('comparison-original', [reference['path']], 240, jsonl([row['original'] for row in rows])),
    ]
    image = out / 'native/candidate-owned.so'
    for partition in cases.PARTITIONS:
        expected_stages.append(('native-' + partition, [python, '-I', '-S', '-B',
            repository / (PREFIX + 'qualification/native_cases.py'), '--image', image,
            '--image-sha256', production['sha256'], '--cases', out / 'cases.json.xz',
            '--partition', partition, '--output', out / partition], 240, b''))
    observed = out / observer['retained']
    expected_stages.extend([
        ('observer-compile', [tools['cc']['path'], '-std=c11', '-O2', '-fPIC', '-Wall', '-Wextra', '-Werror',
            '-c', repository / 'hia/platform/pq_auth/qualification/allocator_observer.c', '-o', out / 'observer/observer.o'], 180, b''),
        ('observer-link', [tools['ld']['path'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
            '-z', 'relro', '-z', 'now', '--build-id=none', '--hash-style=both', '--wrap=calloc', '--wrap=free',
            '--version-script=' + str(out / 'observer/observer.map'), out / 'observer/observer.o',
            *[out / 'native' / name for name in objects], '-lc', '-lpthread', '-o', observed], 180, b''),
        ('observer-symbols', [tools['nm']['path'], '-D', '--defined-only', observed], 180, b''),
        ('allocations', [python, '-I', '-S', '-B', repository / (PREFIX + 'qualification/allocations.py'),
            '--image', observed, '--image-sha256', observer['sha256'], '--fixtures', out / 'fixtures-original.stdout.raw',
            '--output', out / 'allocations'], 180, b''),
        ('lifetimes', [python, '-I', '-S', '-B', repository / (PREFIX + 'qualification/lifetimes.py'),
            '--image', image, '--image-sha256', production['sha256'], '--fixtures', out / 'fixtures-original.stdout.raw',
            '--output', out / 'lifetimes'], 180, b''),
        ('alias-original', [reference['path']], 240, jsonl([row['original'] for row in aliases])),
        ('header-compile', [tools['cc']['path'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-I', repository / PREFIX, repository / (PREFIX + 'qualification/abi_client.c'), image,
            '-Wl,-rpath,' + str(image.parent), '-o', out / 'header-client'], 180, b''),
        ('header-client', [out / 'header-client'], 180, b''),
    ])
    need(len(value['stages']) == len(expected_stages) == 21, 'complete actual stage roster missing')
    for row, (name, argv, limit, data) in zip(value['stages'], expected_stages):
        stage(root, row, name, argv, repository, limit, data)
    need(read(root, 'git-head.stdout.raw') == (value['source_commit_observed'] + '\n' +
         value['source_tree_observed'] + '\n').encode()
         and read(root, 'git-status.stdout.raw').decode() == value['source_dirty_observed'], 'source lineage observation differs')
    actual_aliases = [document(line) for line in read(root, 'alias-original.stdout.raw').splitlines()]
    need(actual_aliases == [row['native'] for row in aliases] and len(actual_aliases) == 2
         and value.get('alias_original_pairs') == 2 and value.get('native_original_pairs') == len(rows) + 2,
         'borrowed-owner alias original/native mismatch')
    need(document(read(root, 'header-client.stdout.raw')) ==
         {'status': 'PASS', 'algorithms': 2, 'public_entries_used': 25}, 'header consumer incomplete')
    files = value.get('files')
    need(type(files) is dict and files, 'missing retained artifact inventory')
    for name, expected in files.items():
        bound(root, relative(name), expected)
    actual_files = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()
                   and path.relative_to(root).as_posix() != 'report.json'
                   and not path.relative_to(root).as_posix().startswith('original/target/')}
    need(actual_files == set(files), 'retained artifact roster changed')
    need(type(value.get('seconds')) in (int, float) and math.isfinite(value['seconds'])
         and value['seconds'] >= sum(row['seconds'] for row in value['stages']), 'invalid total qualification duration')
    return {'status': 'PASS', **COUNTS, 'lifetime_abi_calls': lifetime['abi_calls'],
        'real_process_controls': controls, 'source_files': len(sources), 'source_set_sha256': digest,
        'source_commit_observed': value['source_commit_observed'], 'source_tree_observed': value['source_tree_observed'],
        'source_dirty_observed': value['source_dirty_observed'], 'production_image': production,
        'qualification_report_sha256': sha(read(root, 'report.json')), 'limits': LIMITS,
        'files_read': len(files)}


def validate(root, source_root=ROOT, expected_source_sha256=None):
    from hia.platform.pq_candidate.qualification.integrity import NAMES
    root = regular(root, directory=True)
    report = document(read(root, 'report.json'))
    integrity = document(read(root, 'integrity.json'))
    need(report.get('status') == 'PASS' and integrity.get('status') == 'PASS'
         and integrity.get('run') == len(NAMES) and len(integrity.get('cases', [])) == len(NAMES)
         and [row.get('name') for row in integrity['cases']] == list(NAMES)
         and all(row.get('status') == 'REJECTED' for row in integrity['cases']), 'reader integrity controls incomplete')
    executed = document(read(root, 'executed-report.json'))
    need(executed.get('status') == 'EXECUTED' and all(same(executed.get(name), value)
         for name, value in report.items() if name not in ('status', 'files', 'seconds')),
         'executed evidence was changed after the integrity controls')
    result = validate_evidence(root, source_root, expected_source_sha256)
    result['reader_integrity_controls'] = len(NAMES)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--source-sha256')
    args = parser.parse_args()
    print(json.dumps(validate(args.report, args.source_root, args.source_sha256), sort_keys=True))

