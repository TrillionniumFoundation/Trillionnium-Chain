"""Reader refusal controls over actual completed Candidate evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import copy
import gzip
import os

from hia.platform.pq_candidate.qualification import contract
from hia.platform.pq_candidate.qualification.contract import canonical, document, need, read
from hia.platform.pq_auth.qualification import contract as shared_contract
from hia.platform.pq_auth import readback as shared_reader
from hia.tools import qualify_ml_dsa

NAMES = (
    'failed-report', 'promoted-scope', 'missing-source', 'changed-canonical-dependency',
    'changed-retained-input', 'duplicate-report-json', 'path-traversal', 'symlink-input', 'hardlink-input',
    'wrong-compiler-pin', 'changed-compiler-wire', 'changed-core', 'changed-native-object',
    'changed-composition', 'filtered-native-command', 'omitted-native-case', 'duplicated-native-case',
    'changed-native-observation', 'omitted-native-call', 'filtered-original-command',
    'changed-original-profile', 'changed-original-executable', 'changed-original-request',
    'changed-provider-input', 'omitted-allocation-position', 'denial-was-not-oom', 'unwiped-runtime-free',
    'invalid-parameter-seed-not-consumed', 'missing-real-concurrency', 'changed-live-view',
    'failed-header-consumer', 'changed-stage-timeout', 'changed-reference-executable', 'extra-public-export',
    'observer-replaced-production-object', 'missing-provider-recheck', 'missing-control-roster',
    'missing-process-supervisor', 'raised-native-execution-budget', 'raised-process-cleanup-budget',
    'repeated-process-group-kill', 'unreaped-process-group', 'reset-cleanup-deadline',
    'omitted-actual-grandchild-reap', 'injected-denial-promoted-to-cleanup',
    'changed-native-partition-command', 'omitted-real-supervision-control', 'omitted-reaper-deadline-control',
    'nonfinite-process-clock', 'supervisor-time-exceeds-stage', 'invalid-mode-fixture',
    'wrong-mode-accepted', 'omitted-original-method', 'changed-captured-tool',
    'changed-alias-observation', 'changed-original-lineage',
    'missing-physical-admission-source', 'omitted-admission-source-row', 'changed-admission-source',
)


def controls(root, source_root):
    from hia.platform.pq_candidate import readback as reader
    root, source_root = Path(root), Path(source_root)
    baseline = document(read(root, 'report.json'))
    sources = baseline['source_inputs']
    build = document(read(root, 'native/build.json'))
    original = document(read(root, 'original/report.json'))
    results = []

    def attempt(name, function, expected):
        try:
            function()
        except (ValueError, FileNotFoundError) as error:
            need(expected in str(error), 'negative control hit another rejection: ' + name + ': ' + str(error))
            results.append({'name': name, 'status': 'REJECTED', 'error': str(error), 'type': type(error).__name__})
        else:
            raise ValueError('reader accepted adversarial evidence: ' + name)

    def mutate(changes, function, canonical_inputs=False):
        def altered(directory, name):
            path = Path(directory) / name
            return changes[path] if path in changes else read(directory, name)
        with patch.object(reader, 'read', altered), patch.object(shared_reader, 'read', altered), \
                patch.object(qualify_ml_dsa, 'read', altered):
            if canonical_inputs:
                with patch.object(contract, 'read', altered), patch.object(shared_contract, 'read', altered):
                    return function()
            return function()

    def changed_report(name, value):
        changed = copy.deepcopy(baseline)
        changed[name] = value
        return {root / 'report.json': canonical(changed)}

    def full():
        return reader.validate_evidence(root, source_root)

    def native():
        return reader.validate_native_build(root, source_root, sources,
            Path(baseline['repository']), Path(baseline['output']), baseline['python'])

    def cases():
        return reader.validate_cases(root, source_root, baseline['production_image']['sha256'])

    fixtures = reader.cases.fixture_map(reader.cases.fixture_requests(),
        [document(line) for line in read(root, 'fixtures-original.stdout.raw').splitlines()])

    def ownership():
        return reader.validate_ownership(root, source_root, baseline['production_image']['sha256'],
            baseline['observer_image']['sha256'], fixtures)

    def original_gate(value):
        with reader.original_source(source_root):
            return qualify_ml_dsa.validate_original(value, root / 'original', sources)

    attempt(NAMES[0], lambda: mutate(changed_report('status', 'FAIL'), full), 'incomplete or promoted')
    attempt(NAMES[1], lambda: mutate(changed_report('limits', dict(baseline['limits'], whole_crypto_crate_ported=True)), full), 'incomplete or promoted')
    omitted = dict(sources)
    omitted.pop('hia/src/crypto/pq_candidate_gate.hepta')
    attempt(NAMES[2], lambda: mutate(changed_report('source_inputs', omitted), full), 'changed source graph')
    name = 'hia/src/crypto/keccak_stream.hepta'
    attempt(NAMES[3], lambda: mutate({source_root / name: read(source_root, name) + b'\n'}, full, True), 'changed source graph')
    attempt(NAMES[4], lambda: mutate({root / ('inputs/' + name): read(root, 'inputs/' + name) + b'\n'}, full), 'retained source changed')
    duplicate = read(root, 'report.json').replace(b'{', b'{"status":"PASS",', 1)
    attempt(NAMES[5], lambda: mutate({root / 'report.json': duplicate}, full), 'duplicate JSON field')
    attempt(NAMES[6], lambda: read(root, '../report.json'), 'noncanonical relative path')
    with TemporaryDirectory(prefix='candidate-reader-path-', dir=root.parent) as temporary:
        directory = Path(temporary)
        (directory / 'regular').write_bytes(b'qualification fixture')
        (directory / 'symbolic').symlink_to(directory / 'regular')
        attempt(NAMES[7], lambda: read(directory, 'symbolic'), 'symlinked qualification path')
        os.link(directory / 'regular', directory / 'hard')
        attempt(NAMES[8], lambda: read(directory, 'hard'), 'hardlinked qualification input')
    changed = copy.deepcopy(build)
    changed['builds'][0]['receipt']['compiler_sha256'] = '0' * 64
    attempt(NAMES[9], lambda: mutate({root / 'native/build.json': canonical(changed)}, native), 'native compiler receipt mismatch')
    invocation = next(row for row in build['native_invocations'] if row['unit'] == 'candidate'
                      and row['argv'][0].startswith('/proc/self/fd/'))
    name = 'native/' + invocation['name'] + '.stdin.raw'
    attempt(NAMES[10], lambda: mutate({root / name: read(root, name) + b'\n'}, native), 'native request receipt differs')
    core = document(read(root, 'native/candidate.core.json'))
    core['module'] = 'changed'
    attempt(NAMES[11], lambda: mutate({root / 'native/candidate.core.json': canonical(core)}, native), 'native Core differs')
    raw = read(root, 'native/candidate.o')
    attempt(NAMES[12], lambda: mutate({root / 'native/candidate.o': raw[:-1] + bytes([raw[-1] ^ 1])}, native), 'native compiler receipt mismatch')
    attempt(NAMES[13], lambda: mutate({root / 'native/candidate.hepta': read(root, 'native/candidate.hepta') + b'\n'}, native), 'native composition changed')
    changed = copy.deepcopy(build)
    row = changed['stages'][1]
    row['argv'][-2] = '/tmp/unrelated-object.o'
    attempt(NAMES[14], lambda: mutate({root / 'native/build.json': canonical(changed),
        root / ('native/' + row['name'] + '.receipt.json'): canonical(row)}, native), 'changed or unsuccessful stage')
    name = 'methods/native-values.jsonl.gz'
    values = [document(line) for line in gzip.decompress(read(root, name)).splitlines()]
    for index, modified in ((15, values[:-1]), (16, [*values[:-1], values[0]])):
        raw = b'\n'.join(canonical(item) for item in modified) + b'\n'
        attempt(NAMES[index], lambda raw=raw: mutate({root / name: gzip.compress(raw)}, cases), 'native case omitted')
    changed = copy.deepcopy(values)
    changed[0]['result']['name'] = 'changed'
    attempt(NAMES[17], lambda: mutate({root / name: gzip.compress(b'\n'.join(canonical(row) for row in changed) + b'\n')}, cases), 'native observation differs')
    raw = gzip.decompress(read(root, 'methods/native-calls.jsonl.gz')).splitlines(keepends=True)
    attempt(NAMES[18], lambda: mutate({root / 'methods/native-calls.jsonl.gz': gzip.compress(b''.join(raw[:-1]))}, cases), 'native ABI calls omitted')
    changed = copy.deepcopy(original)
    row = next(row for row in changed['stages'] if row['label'] == 'cargo-clippy')
    row['argv'] = row['argv'][:-2]
    attempt(NAMES[19], lambda: mutate({root / ('original/' + row['label'] + '.receipt.json'): canonical(row)},
        lambda: original_gate(changed)), 'Changed, filtered or unsuccessful original stage')
    changed = copy.deepcopy(original)
    changed['tests'][0]['profile']['overflow_checks'] = False
    attempt(NAMES[20], lambda: original_gate(changed), 'Original test compilation profile differs')
    name = 'original/' + original['tests'][0]['retained']
    raw = read(root, name)
    attempt(NAMES[21], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])}, lambda: original_gate(original)), 'Changed original test executable')
    row = next(row for row in baseline['stages'] if row['name'] == 'comparison-original')
    incoming = read(root, 'comparison-original.stdin.raw')
    attempt(NAMES[22], lambda: mutate({root / 'comparison-original.stdin.raw': incoming + b'\n'},
        lambda: reader.stage(root, row, row['name'], row['argv'], row['cwd'], 240, incoming)), 'stage request differs')
    provider = document(read(root, 'provider.json'))
    name = 'provider/00-' + Path(provider['native_backend_inputs'][0]['path']).name
    raw = read(root, name)
    def provider_gate():
        with reader.original_source(source_root):
            return qualify_ml_dsa.validate_provider(provider, retained=root)
    attempt(NAMES[23], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])}, provider_gate), 'Changed actual provider input')
    rows = document(read(root, 'allocations/controls.json'))
    attempt(NAMES[24], lambda: mutate({root / 'allocations/controls.json': canonical(rows[:-1])}, ownership), 'incomplete allocation controls')
    changed = copy.deepcopy(rows)
    changed[1]['result_status'] = 104
    attempt(NAMES[25], lambda: mutate({root / 'allocations/controls.json': canonical(changed)}, ownership), 'allocation failure position omitted')
    changed = copy.deepcopy(rows)
    changed[0]['after_cleanup'][6] += 1
    attempt(NAMES[26], lambda: mutate({root / 'allocations/controls.json': canonical(changed)}, ownership), 'runtime freed an unwiped')
    changed = copy.deepcopy(rows)
    changed[-1]['after_cleanup'][1] -= 1
    attempt(NAMES[27], lambda: mutate({root / 'allocations/controls.json': canonical(changed)}, ownership), 'invalid-parameter seed was not consumed')
    lifetime = document(read(root, 'lifetimes/report.json'))
    lifetime['threads'][1]['thread'] = lifetime['threads'][0]['thread']
    attempt(NAMES[28], lambda: mutate({root / 'lifetimes/report.json': canonical(lifetime)}, ownership), 'real parallel owner readers missing')
    calls = document(read(root, 'lifetimes/calls.json'))
    next(row for row in calls if row.get('has_data'))['size'] += 1
    attempt(NAMES[29], lambda: mutate({root / 'lifetimes/calls.json': canonical(calls)}, ownership), 'lifetime borrowed view was truncated')
    row = next(row for row in baseline['stages'] if row['name'] == 'header-client')
    attempt(NAMES[30], lambda: reader.stage(root, dict(row, exit_code=7), row['name'], row['argv'], row['cwd'], 180), 'changed or unsuccessful stage')
    attempt(NAMES[31], lambda: reader.stage(root, dict(row, wall_limit_seconds=1), row['name'], row['argv'], row['cwd'], 180), 'changed or unsuccessful stage')
    reference = baseline['original_reference']
    name = 'original/' + reference['retained']
    raw = read(root, name)
    attempt(NAMES[32], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])},
        lambda: reader.bound(root, name, reference)), 'changed retained bytes')
    name = 'native/public-symbols.stdout.raw'
    attempt(NAMES[33], lambda: mutate({root / name: read(root, name) + b'0 T private_f0\n'}, native), 'changed retained bytes')
    changed = copy.deepcopy(baseline['observer_production_objects'])
    changed['candidate-private.o']['sha256'] = '0' * 64
    attempt(NAMES[34], lambda: mutate(changed_report('observer_production_objects', changed), full), 'observer changed production objects')
    attempt(NAMES[35], lambda: mutate(changed_report('provider_inputs_unchanged_after_all_execution', False), full), 'actual live provider was not rechecked')
    changed = dict(baseline, status='PASS')
    attempt(NAMES[36], lambda: mutate({root / 'report.json': canonical(changed),
        root / 'integrity.json': canonical({'status': 'PASS', 'run': 0, 'cases': []})},
        lambda: reader.validate(root, source_root)), 'reader integrity controls incomplete')
    observed = next(row for row in baseline['stages'] if row['name'] == 'native-verify-87')
    def stage_change(index, changed, expected):
        attempt(NAMES[index], lambda: mutate({root / (changed['name'] + '.receipt.json'): canonical(changed)},
            lambda: reader.stage(root, changed, observed['name'], observed['argv'], observed['cwd'], 240)), expected)
    changed = copy.deepcopy(observed)
    changed.pop('supervision')
    stage_change(37, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed)
    changed['supervision']['execution_limit_seconds'] = 600
    stage_change(38, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed)
    changed['supervision']['cleanup_limit_seconds'] = 6
    stage_change(39, changed, 'changed supervision execution/cleanup contract')
    changed = copy.deepcopy(observed)
    changed['supervision']['killpg_attempts'] = [{'signal': 9, 'errno': 0,
        'monotonic': changed['supervision']['cleanup_started_monotonic']}] * 2
    stage_change(40, changed, 'repeated or unbound process-group cleanup')
    changed = copy.deepcopy(observed)
    changed['supervision']['group_absent'] = False
    stage_change(41, changed, 'incomplete or unsuccessful process supervision')
    changed = copy.deepcopy(observed)
    changed['supervision']['cleanup_deadline_monotonic'] += 3
    stage_change(42, changed, 'changed supervision clock or reset cleanup deadline')
    process_report = document(read(root, 'supervision-controls/report.json'))
    def process_controls():
        return reader.validate_supervision_controls(root, source_root, Path(baseline['repository']),
            Path(baseline['output']), baseline['python'])
    changed = copy.deepcopy(process_report)
    child = next(row for row in changed['cases'] if row['name'] == 'group-timeout')
    child['receipt']['adopted_reaped'] = []
    attempt(NAMES[43], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed),
        root / 'supervision-controls/group-timeout.receipt.json': canonical(child['receipt'])}, process_controls), 'actual adopted grandchild was not reaped')
    changed = copy.deepcopy(process_report)
    child = next(row for row in changed['cases'] if row['name'] == 'cleanup-denied')
    child['receipt']['cleanup_complete'] = True
    attempt(NAMES[44], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed),
        root / 'supervision-controls/cleanup-denied.receipt.json': canonical(child['receipt'])}, process_controls), 'injected kill denial was promoted')
    changed = copy.deepcopy(observed)
    changed['argv'][changed['argv'].index('--partition') + 1] = 'methods'
    stage_change(45, changed, 'changed or unsuccessful stage')
    changed = copy.deepcopy(process_report)
    changed['cases'] = changed['cases'][:-1]
    attempt(NAMES[46], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed)}, process_controls), 'supervision control roster incomplete')
    changed = copy.deepcopy(process_report)
    changed.pop('reaper_deadline_control')
    attempt(NAMES[47], lambda: mutate({root / 'supervision-controls/report.json': canonical(changed)}, process_controls), 'reaper deadline boundary control omitted')
    changed = copy.deepcopy(observed)
    changed['supervision']['seconds'] = float('inf')
    raw = canonical(changed).replace(b'Infinity', b'1e999')
    attempt(NAMES[48], lambda: mutate({root / (changed['name'] + '.receipt.json'): raw},
        lambda: reader.stage(root, changed, observed['name'], observed['argv'], observed['cwd'], 240)), 'invalid supervision clock')
    changed = copy.deepcopy(observed)
    changed['supervision']['seconds'] = changed['seconds'] + 1
    stage_change(49, changed, 'stage duration is shorter')
    validity = read(root, 'mode-validity-original.stdout.raw').splitlines()
    validity[0] = canonical({'code': 7, 'expected': 0, 'actual': 0})
    attempt(NAMES[50], lambda: mutate({root / 'mode-validity-original.stdout.raw': b'\n'.join(validity) + b'\n'}, cases), 'mode-separation fixtures were not accepted')
    values = [document(line) for line in gzip.decompress(read(root, 'verify-65/native-values.jsonl.gz')).splitlines()]
    next(row for row in values if row['label'] == '65-mode-65-context')['result']['code'] = 0
    attempt(NAMES[51], lambda: mutate({root / 'verify-65/native-values.jsonl.gz': gzip.compress(
        b'\n'.join(canonical(row) for row in values) + b'\n')}, cases), 'native observation differs')
    attempt(NAMES[52], lambda: mutate(changed_report('original_method_roster', baseline['original_method_roster'][:-1]), full), 'original public method roster omitted')
    name = baseline['tools']['python']['retained']
    raw = read(root, name)
    attempt(NAMES[53], lambda: mutate({root / name: raw[:-1] + bytes([raw[-1] ^ 1])}, full), 'changed retained bytes')
    alias = document(read(root, 'lifetimes/alias-original-65.json'))
    alias['native']['pk'] = '00'
    attempt(NAMES[54], lambda: mutate({root / 'lifetimes/alias-original-65.json': canonical(alias)}, full), 'borrowed-owner alias original/native mismatch')
    attempt(NAMES[55], lambda: mutate(changed_report('source_commit_observed', '0' * 40), full), 'original lineage or report mismatch')
    name = 'hia/src/crypto/pq_auth_owner.hepta'
    need(name in sources, 'global component admission source was not captured')
    with TemporaryDirectory(prefix='candidate-reader-admission-', dir=root.parent) as temporary:
        directory = Path(temporary)
        for source in sources:
            target = directory / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(read(source_root, source))
        need(contract.input_map(directory, git_original=False) == sources, 'admission fixture source graph differs')
        (directory / name).unlink()
        attempt(NAMES[56], lambda: reader.validate_evidence(root, directory, contract.sha(canonical(sources))),
            'pq_auth_owner.hepta')
    omitted = dict(sources)
    omitted.pop(name)
    attempt(NAMES[57], lambda: mutate(changed_report('source_inputs', omitted), full), 'changed source graph')
    attempt(NAMES[58], lambda: mutate({source_root / name: read(source_root, name) + b'\n'}, full, True),
        'changed source graph')
    need([row['name'] for row in results] == list(NAMES), 'incomplete reader control roster')
    return {'status': 'PASS', 'run': len(results), 'cases': results,
            'scope': 'mutated retained evidence is refused; native executions are not synthesized'}
