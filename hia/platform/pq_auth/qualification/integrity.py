"""Adversarial readback controls over the actual completed qualification bytes."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import copy
import gzip
import json
import lzma
import os

from hia.platform.pq_auth.qualification import contract
from hia.platform.pq_auth.qualification.contract import (PREFIX, canonical, document, need,
    read, sha)
from hia.tools import qualify_ml_dsa

NAMES = (
    'failed-report', 'promoted-scope', 'missing-source', 'changed-canonical-dependency',
    'changed-retained-input', 'duplicate-report-json', 'path-traversal', 'symlink-input',
    'hardlink-input', 'wrong-compiler-pin', 'changed-compiler-wire', 'changed-core',
    'changed-native-object', 'changed-composition', 'filtered-native-command',
    'omitted-native-case', 'duplicated-native-case', 'changed-native-observation',
    'omitted-native-call', 'filtered-original-command', 'changed-original-profile',
    'changed-original-executable', 'changed-original-request', 'changed-provider-input',
    'omitted-allocation-position', 'denial-was-not-oom', 'unwiped-runtime-free',
    'missing-real-concurrency', 'truncated-live-view', 'failed-header-consumer',
    'changed-stage-timeout', 'changed-adapter-executable', 'extra-public-export',
    'observer-replaced-production-object', 'missing-provider-recheck', 'missing-control-roster',
    'missing-process-supervisor', 'raised-native-execution-budget', 'raised-process-cleanup-budget',
    'repeated-process-group-kill', 'unreaped-process-group', 'reset-cleanup-deadline',
    'omitted-actual-grandchild-reap', 'injected-denial-promoted-to-cleanup',
    'changed-native-partition-command', 'omitted-real-supervision-control', 'omitted-reaper-deadline-control',
    'nonfinite-process-clock', 'supervisor-time-exceeds-stage',
)


def controls(root, source_root):
    from hia.platform.pq_auth import readback as reader
    root, source_root = Path(root), Path(source_root)
    baseline = document(read(root, 'report.json'))
    sources = baseline['source_inputs']
    build = document(read(root, 'native/build.json'))
    original = document(read(root, 'original/report.json'))
    native_cases = document(lzma.decompress(read(root, 'methods/cases.json.xz')))
    results = []
    def attempt(name, function, expected):
        try:
            function()
        except (ValueError, FileNotFoundError) as error:
            need(expected in str(error), 'negative control hit a different rejection: ' + name + ': ' + str(error))
            results.append({'name': name, 'status': 'REJECTED', 'error': str(error), 'type': type(error).__name__})
        else:
            raise ValueError('reader accepted adversarial evidence: ' + name)

    def mutate(changes, function, *, canonical_inputs=False):
        raw_read = read
        def altered(directory, name):
            path = Path(directory) / name
            if path in changes:
                return changes[path]
            return raw_read(directory, name)
        with patch.object(reader, 'read', altered), patch.object(qualify_ml_dsa, 'read', altered):
            if canonical_inputs:
                with patch.object(contract, 'read', altered):
                    return function()
            return function()

    def report_change(key, value):
        modified = copy.deepcopy(baseline)
        modified[key] = value
        return {root / 'report.json': canonical(modified)}

    def full():
        return reader.validate_evidence(root, source_root)

    def native():
        return reader.validate_native_build(root, source_root, sources, Path(baseline['repository']),
            Path(baseline['output']), baseline['python'])

    def cases():
        return reader.validate_cases(root, source_root, baseline['production_image']['sha256'])

    def ownership():
        return reader.validate_ownership(root, source_root, baseline['production_image']['sha256'], baseline['observer_image']['sha256'])

    def original_gate(value):
        with reader.original_source(source_root):
            return qualify_ml_dsa.validate_original(value, root / 'original', sources)

    attempt(NAMES[0], lambda: mutate(report_change('status', 'FAIL'), full), 'incomplete or promoted')
    promoted = dict(baseline['limits'], whole_crypto_crate_ported=True)
    attempt(NAMES[1], lambda: mutate(report_change('limits', promoted), full), 'incomplete or promoted')
    omitted = dict(sources)
    omitted.pop('hia/src/crypto/pq_frame.hepta')
    attempt(NAMES[2], lambda: mutate(report_change('source_inputs', omitted), full), 'changed source graph')
    name = 'hia/src/crypto/sha256_stream.hepta'
    attempt(NAMES[3], lambda: mutate({source_root / name: read(source_root, name) + b'\n'}, full, canonical_inputs=True), 'changed source graph')
    attempt(NAMES[4], lambda: mutate({root / 'inputs' / name: read(root, 'inputs/' + name) + b'\n'}, full), 'retained source changed')
    duplicate = read(root, 'report.json').replace(b'{', b'{"status":"PASS",', 1)
    attempt(NAMES[5], lambda: mutate({root / 'report.json': duplicate}, full), 'duplicate JSON field')
    attempt(NAMES[6], lambda: read(root, '../report.json'), 'noncanonical relative path')
    with TemporaryDirectory(prefix='pq-reader-path-control-', dir=root.parent) as temp:
        directory = Path(temp)
        (directory / 'regular').write_bytes(b'private fixture')
        (directory / 'symbolic').symlink_to(directory / 'regular')
        attempt(NAMES[7], lambda: read(directory, 'symbolic'), 'symlinked qualification path')
        os.link(directory / 'regular', directory / 'hard')
        attempt(NAMES[8], lambda: read(directory, 'hard'), 'hardlinked qualification input')

    changed = copy.deepcopy(build)
    changed['builds'][0]['receipt']['compiler_sha256'] = '0' * 64
    attempt(NAMES[9], lambda: mutate({root / 'native/build.json': canonical(changed)}, native), 'native compiler receipt mismatch')
    compiler_call = next(row for row in build['native_invocations'] if row['unit'] == 'auth' and row['argv'][0].startswith('/proc/self/fd/'))
    wire_name = 'native/' + compiler_call['name'] + '.stdin.raw'
    attempt(NAMES[10], lambda: mutate({root / wire_name: read(root, wire_name) + b'\n'}, native), 'native request receipt differs')
    core_name = 'native/auth.core.json'
    core = document(read(root, core_name))
    core['module'] = 'different'
    attempt(NAMES[11], lambda: mutate({root / core_name: canonical(core)}, native), 'native Core differs')
    raw = read(root, 'native/auth.o')
    attempt(NAMES[12], lambda: mutate({root / 'native/auth.o': raw[:-1] + bytes([raw[-1] ^ 1])}, native), 'native compiler receipt mismatch')
    attempt(NAMES[13], lambda: mutate({root / 'native/auth.hepta': read(root, 'native/auth.hepta') + b'\n'}, native), 'native composition changed')
    changed = copy.deepcopy(build)
    changed['stages'][1]['argv'][-2] = '/tmp/unrelated-object.o'
    row = changed['stages'][1]
    attempt(NAMES[14], lambda: mutate({root / 'native/build.json': canonical(changed), root / ('native/' + row['name'] + '.receipt.json'): canonical(row)}, native), 'changed or unsuccessful stage')
    for index, selected in ((15, native_cases[:-1]), (16, [*native_cases[:-1], native_cases[0]])):
        attempt(NAMES[index], lambda selected=selected: mutate({root / 'methods/cases.json.xz': lzma.compress(canonical(selected))}, cases), 'native case omitted')
    changed_cases = copy.deepcopy(native_cases)
    changed_cases[0]['native']['code'] = 99
    attempt(NAMES[17], lambda: mutate({root / 'methods/cases.json.xz': lzma.compress(canonical(changed_cases))}, cases), 'native case omitted')
    raw_calls = gzip.decompress(read(root, 'methods/native-calls.jsonl.gz')).splitlines(keepends=True)
    attempt(NAMES[18], lambda: mutate({root / 'methods/native-calls.jsonl.gz': gzip.compress(b''.join(raw_calls[:-1]))}, cases), 'native ABI calls were omitted')
    changed = copy.deepcopy(original)
    row = next(row for row in changed['stages'] if row['label'] == 'cargo-clippy')
    row['argv'] = row['argv'][:-2]
    attempt(NAMES[19], lambda: mutate({root / ('original/' + row['label'] + '.receipt.json'): canonical(row)}, lambda: original_gate(changed)), 'Changed, filtered or unsuccessful original stage')
    changed = copy.deepcopy(original)
    changed['tests'][0]['profile']['overflow_checks'] = False
    attempt(NAMES[20], lambda: original_gate(changed), 'Original test compilation profile differs')
    name = 'original/' + original['tests'][0]['retained']
    raw = read(root, name)
    attempt(NAMES[21], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])}, lambda: original_gate(original)), 'Changed original test executable')
    row = next(row for row in baseline['stages'] if row['name'] == 'compare-auth')
    incoming = read(root, 'compare-auth.stdin.raw')
    attempt(NAMES[22], lambda: mutate({root / 'compare-auth.stdin.raw': incoming + b'\n'},
        lambda: reader.stage(root, row, row['name'], row['argv'], row['cwd'], row['wall_limit_seconds'], incoming)), 'stage request differs')
    provider = document(read(root, 'provider.json'))
    name = 'provider/00-' + Path(provider['native_backend_inputs'][0]['path']).name
    raw = read(root, name)
    def provider_gate():
        with reader.original_source(source_root):
            return qualify_ml_dsa.validate_provider(provider, retained=root)
    attempt(NAMES[23], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])}, provider_gate), 'Changed actual provider input')
    rows = document(read(root, 'allocations/controls.json'))
    attempt(NAMES[24], lambda: mutate({root / 'allocations/controls.json': canonical(rows[:-1])}, ownership), 'incomplete allocation controls')
    changed_rows = copy.deepcopy(rows)
    changed_rows[1]['result_status'] = 104
    attempt(NAMES[25], lambda: mutate({root / 'allocations/controls.json': canonical(changed_rows)}, ownership), 'allocation failure position omitted')
    changed_rows = copy.deepcopy(rows)
    changed_rows[0]['after_cleanup'][6] += 1
    attempt(NAMES[26], lambda: mutate({root / 'allocations/controls.json': canonical(changed_rows)}, ownership), 'runtime freed an unwiped')
    lifetime = document(read(root, 'lifetimes/report.json'))
    lifetime['threads'][1]['thread'] = lifetime['threads'][0]['thread']
    attempt(NAMES[27], lambda: mutate({root / 'lifetimes/report.json': canonical(lifetime)}, ownership), 'real parallel owner readers missing')
    calls = document(read(root, 'lifetimes/calls.json'))
    next(row for row in calls if row.get('data_hex'))['data_hex'] = ''
    attempt(NAMES[28], lambda: mutate({root / 'lifetimes/calls.json': canonical(calls)}, ownership), 'lifetime view bytes truncated')
    row = next(row for row in baseline['stages'] if row['name'] == 'header-client')
    bad = dict(row, exit_code=7)
    attempt(NAMES[29], lambda: reader.stage(root, bad, row['name'], row['argv'], row['cwd'], row['wall_limit_seconds']), 'changed or unsuccessful stage')
    bad = dict(row, wall_limit_seconds=1)
    attempt(NAMES[30], lambda: reader.stage(root, bad, row['name'], row['argv'], row['cwd'], row['wall_limit_seconds']), 'changed or unsuccessful stage')
    adapter = baseline['original_adapters']['auth']
    raw = read(root, adapter['retained'])
    attempt(NAMES[31], lambda: mutate({root / adapter['retained']: raw[:-1] + bytes([raw[-1] ^ 1])},
        lambda: reader.bound(root, adapter['retained'], adapter)), 'changed retained bytes')
    attempt(NAMES[32], lambda: mutate({root / 'native/public-symbols.stdout.raw': read(root, 'native/public-symbols.stdout.raw') + b'0000000000000000 T private_f0\n'}, native), 'changed retained bytes')
    wrong = copy.deepcopy(baseline['observer_production_objects'])
    wrong['auth-private.o']['sha256'] = '0' * 64
    attempt(NAMES[33], lambda: mutate(report_change('observer_production_objects', wrong), full), 'observer changed production objects')
    attempt(NAMES[34], lambda: mutate(report_change('provider_inputs_unchanged_after_adapter_links', False), full), 'actual live provider was not checked')
    missing = copy.deepcopy(baseline)
    missing['status'] = 'PASS'
    attempt(NAMES[35], lambda: mutate({root / 'report.json': canonical(missing), root / 'integrity.json': canonical({'status': 'PASS', 'run': 0, 'cases': []})},
        lambda: reader.validate(root, source_root)), 'reader integrity controls incomplete')
    observed_stage = next(row for row in baseline['stages'] if row['name'] == 'native-extended-max-sign')
    def stage_change(index, changed, expected):
        attempt(NAMES[index], lambda: mutate({root / (changed['name'] + '.receipt.json'): canonical(changed)},
            lambda: reader.stage(root, changed, observed_stage['name'], observed_stage['argv'],
                                 observed_stage['cwd'], 240)), expected)
    changed = copy.deepcopy(observed_stage)
    changed.pop('supervision')
    stage_change(36, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['execution_limit_seconds'] = 600
    stage_change(37, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['cleanup_limit_seconds'] = 6
    stage_change(38, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['killpg_attempts'] = [{'signal': 9, 'errno': 0,
        'monotonic': changed['supervision']['cleanup_started_monotonic']}] * 2
    stage_change(39, changed, 'repeated or unbound process-group cleanup')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['group_absent'] = False
    stage_change(40, changed, 'incomplete or unsuccessful process supervision')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['cleanup_deadline_monotonic'] += 3
    stage_change(41, changed, 'changed supervision clock or reset cleanup deadline')
    controls_report = document(read(root, 'supervision-controls/report.json'))
    def process_controls():
        return reader.validate_supervision_controls(root, source_root, Path(baseline['repository']),
            Path(baseline['output']), baseline['python'])
    changed_controls = copy.deepcopy(controls_report)
    child = next(row for row in changed_controls['cases'] if row['name'] == 'group-timeout')
    child['receipt']['adopted_reaped'] = []
    attempt(NAMES[42], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed_controls),
        root / 'supervision-controls/group-timeout.receipt.json': canonical(child['receipt'])}, process_controls),
        'actual adopted grandchild was not reaped')
    changed_controls = copy.deepcopy(controls_report)
    child = next(row for row in changed_controls['cases'] if row['name'] == 'cleanup-denied')
    child['receipt']['cleanup_complete'] = True
    attempt(NAMES[43], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed_controls),
        root / 'supervision-controls/cleanup-denied.receipt.json': canonical(child['receipt'])}, process_controls),
        'injected kill denial was promoted to actual cleanup')
    changed = copy.deepcopy(observed_stage)
    changed['argv'][changed['argv'].index('--partition') + 1] = 'extended-tail'
    stage_change(44, changed, 'changed or unsuccessful stage')
    changed_controls = copy.deepcopy(controls_report)
    changed_controls['cases'] = changed_controls['cases'][:-1]
    attempt(NAMES[45], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed_controls)},
        process_controls), 'supervision control roster incomplete')
    changed_controls = copy.deepcopy(controls_report)
    changed_controls.pop('reaper_deadline_control')
    attempt(NAMES[46], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed_controls)},
        process_controls), 'reaper deadline boundary control omitted or promoted')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['seconds'] = float('inf')
    raw = canonical(changed).replace(b'Infinity', b'1e999')
    attempt(NAMES[47], lambda: mutate({root / (changed['name'] + '.receipt.json'): raw},
        lambda: reader.stage(root, changed, observed_stage['name'], observed_stage['argv'],
                             observed_stage['cwd'], 240)), 'invalid supervision clock')
    changed = copy.deepcopy(observed_stage)
    changed['supervision']['seconds'] = changed['seconds'] + 1
    stage_change(48, changed, 'stage duration is shorter than actual supervisor')
    need([row['name'] for row in results] == list(NAMES), 'integrity controls omitted or reordered')
    return {'status': 'PASS', 'run': len(NAMES), 'cases': results,
            'baseline_report_sha256': sha(read(root, 'report.json')),
            'source_set_sha256': baseline['source_set_sha256'],
            'fixture_sha256': sha(read(source_root, PREFIX + 'qualification/integrity.py'))}
