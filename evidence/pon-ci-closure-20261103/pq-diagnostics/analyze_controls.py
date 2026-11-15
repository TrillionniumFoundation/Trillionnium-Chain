import collections, datetime, hashlib, json, os, pathlib, re, tempfile, zipfile

BASE = pathlib.Path('/workspace/scratch/abae1861b451/recovered-ci/bebb/pq')
ROOT = pathlib.Path('/workspace/scratch/abae1861b451/chain-recovered')
HEAD = 'bebb1f3289cd7050fefde89ea8f2cf33c6c37588'
MERGE = '0153600a002c420d20128983c3280ff6c16e70c4'
TREE = '58c31e8a6220c6be20029b33cb060f3a2034d1a7'
PREFIX = 'TRNM_PQ_PHASE_DIAGNOSTIC '
CONFIG = ROOT / 'config/pon/pq-system-required-tests-v1.json'
required_bytes = CONFIG.read_bytes()
required = json.loads(required_bytes)['tests']
assert len(required) == 43 and len(set(required)) == 43

phase_names = (
    'request_sign_including_self_verify', 'reply_sign_including_self_verify',
    'service_request_verify', 'client_reply_verify', 'transport', 'local_commit'
)
quality_names = (
    'measurement_unavailable', 'encoding_truncated', 'process_log_limit_reached',
    'child_snapshot_missing_or_invalid', 'has_open_operations'
)

def atomic(path, content):
    fd, tmp = tempfile.mkstemp(prefix='.analysis-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def phase_statistics(diagnostic, selected=None):
    output = {}
    for phase in diagnostic.get('phase_totals', []):
        if selected is not None and phase['phase'] not in selected:
            continue
        sample = phase['samples']
        count = sample['completed']
        complete = sample['unfinished'] == 0 and count > 0
        output[phase['phase']] = {
            **sample,
            'wall_mean_ns': sample['wall_ns'] / count
                if complete and sample['wall_unknown'] == 0 and sample['wall_ns'] is not None else None,
            'cpu_mean_ns': sample['thread_cpu_ns'] / count
                if complete and sample['cpu_unknown'] == 0 and sample['thread_cpu_ns'] is not None else None,
        }
    return output

artifacts = []
for path in sorted(BASE.glob('controls-*.zip')):
    inventory = json.loads(path.with_name(path.stem + '-inventory.json').read_text())
    raw_archive = path.read_bytes()
    assert len(raw_archive) == inventory['bytes']
    assert hashlib.sha256(raw_archive).hexdigest() == inventory['sha256']
    lane = inventory['name'].removeprefix('pq-system-controls-').split('-' + HEAD)[0]
    expected_commit = MERGE if 'prospective-merge' in lane else HEAD
    artifact = {
        'artifact_id': inventory['id'], 'artifact_name': inventory['name'],
        'run_id': 41658914755, 'attempt': 1, 'lane': lane,
        'archive_bytes': inventory['bytes'], 'archive_sha256': inventory['sha256'],
        'archive_url': inventory['source_url'], 'tested_commit': expected_commit,
        'tested_tree': TREE, 'controls': [], 'diagnostic_quality': {},
    }
    flags = collections.Counter({name: 0 for name in quality_names})
    flags.update({
        'measurement_failures': 0, 'snapshots_with_overwritten_records': 0,
        'phase_cpu_unknown_representations': 0, 'phase_wall_unknown_representations': 0,
        'phase_unfinished_representations': 0,
    })
    with zipfile.ZipFile(path) as archive:
        source = json.loads(archive.read('source.json'))
        assert source['candidate'] == HEAD and source['tested_commit'] == expected_commit
        assert source['tested_tree'] == TREE and source['tracked_worktree_verified']
        assert [line.split('\t', 1)[1] for line in archive.read('required-tests.tsv').decode().splitlines()] == required
        artifact['source'] = source
        artifact['build'] = json.loads(archive.read('build.json'))
        assert artifact['build']['exit_code'] == 0
        for index, selector in enumerate(required):
            label = f'native-{index:02d}'
            command = json.loads(archive.read(label + '.json'))
            execution = json.loads(archive.read(label + '-execution.json'))
            raw_log = archive.read(label + '.log')
            log = raw_log.decode()
            assert len(raw_log) == command['log_bytes']
            assert hashlib.sha256(raw_log).hexdigest() == command['log_sha256']
            assert command['exit_code'] == 0 and command['status'] == 'command_succeeded'
            assert execution['result'] == 'PASS' and execution['executed_tests'] == 1
            assert execution['test'] == selector
            assert re.findall(r'^test (\S+) \.\.\. ok$', log, re.M) == [selector]
            for boundary in ('before', 'after'):
                identity = command[boundary]
                assert identity['candidate'] == HEAD and identity['tested_commit'] == expected_commit
                assert identity['tested_tree'] == TREE and identity['tracked_worktree_verified']
            control = {
                'label': label, 'selector': selector, 'exit_code': command['exit_code'],
                'execution': execution, 'command_started_utc': command['started_utc'],
                'command_elapsed_ns': command['elapsed_ns'],
                'command_argv': command['argv'],
                'log_bytes': len(raw_log), 'log_sha256': command['log_sha256'],
                'source_before_after_verified': True, 'snapshots': [],
            }
            lines = log.splitlines()
            assert all(line.startswith(PREFIX) for line in lines if PREFIX in line)
            for line_number, line in enumerate(lines, start=1):
                if not line.startswith(PREFIX):
                    continue
                diagnostic = json.loads(line[len(PREFIX):])
                assert diagnostic['schema'] == 'pon-pq-test-phase-observation-v1'
                snapshot = {
                    'log_line': line_number,
                    'diagnostic_line_sha256': hashlib.sha256(line.encode()).hexdigest(),
                    'metadata': {key: value for key, value in diagnostic.items()
                                 if key not in ('records', 'phase_totals')},
                    'phase_statistics': phase_statistics(diagnostic),
                    'retained_record_ids': [record['id'] for record in diagnostic.get('records', [])],
                    'retained_records': diagnostic.get('records', [])
                        if label in ('native-31', 'native-34', 'native-36') else None,
                }
                control['snapshots'].append(snapshot)
                for key in quality_names:
                    flags[key] += bool(diagnostic.get(key))
                flags['measurement_failures'] += diagnostic.get('measurement_failures', 0)
                flags['snapshots_with_overwritten_records'] += bool(diagnostic.get('records_overwritten', 0))
                for phase in diagnostic.get('phase_totals', []):
                    flags['phase_cpu_unknown_representations'] += phase['samples']['cpu_unknown']
                    flags['phase_wall_unknown_representations'] += phase['samples']['wall_unknown']
                    flags['phase_unfinished_representations'] += phase['samples']['unfinished']
            artifact['controls'].append(control)
        artifact['diagnostic_quality'] = dict(flags)
        artifact['diagnostic_snapshot_count'] = sum(len(control['snapshots']) for control in artifact['controls'])
        artifact['controls_without_diagnostics'] = [control['label'] for control in artifact['controls'] if not control['snapshots']]
    artifacts.append(artifact)

assert len(artifacts) == 4
limitations = [
    'The 172 PASS receipts are four executions of the original 43 exact selectors on one candidate; they are not independent long-run reliability trials.',
    'The original 250 ms exchange cap and 200 ms shared native-31 deadline remain unchanged; diagnostic overhead is charged to those original budgets.',
    'Signature phases include their original self-verification and message preparation; they do not isolate raw ML-DSA primitive signing time.',
    'Phase intervals are nested and not additive. Direct fixture transport includes synchronous service work and the intentional late-reply delay; its CPU overlaps the service phases.',
    'Per-scope totals can include initialization, the target action, and subsequent validation calls. Native-31 has seven exchange samples, not just its one Current/CAS target pair.',
    'Every native-31 final snapshot has 21 overwritten operation rows. Its fixed last_failure retains LIVE_DEADLINE and local_committed=true, but the critical CAS row and individual phase timing are no longer reconstructible.',
    'Eight selectors per lane have no explicitly enabled diagnostic scope; their ordinary exact test receipts are still present and validated.',
    'Zero unknown clock counts or unfinished samples applies only to recorded snapshots in this run; it does not demonstrate cancellation/kill coverage under every schedule.',
    'The expected bad-signature rejection in native-36 records tcp_handle with code=null. Its exact error identity is unknown; no payload text or guessed code is substituted.',
    'This report covers the small pre-regression controls artifacts. Full Node library and strict Clippy job conclusions are separate.',
]
report = {
    'schema': 'trnm-pq-original-budget-phase-audit-v1',
    'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'head_sha': HEAD, 'actual_merge_sha': MERGE, 'tree_sha': TREE,
    'required_selectors': 43, 'validated_control_executions': 172,
    'required_config_sha256': hashlib.sha256(required_bytes).hexdigest(),
    'all_log_sha256_and_bytes_verified': True,
    'all_command_source_before_after_verified': True,
    'limitations': limitations, 'artifacts': artifacts,
}
summary = {
    key: value for key, value in report.items() if key != 'artifacts'
}
summary['lanes'] = []
for artifact in artifacts:
    sample = next(control for control in artifact['controls'] if control['label'] == 'native-31')
    assert len(sample['snapshots']) == 1
    snapshot = sample['snapshots'][0]
    failure = snapshot['metadata']['last_failure']
    assert failure['error']['code'] == 'LIVE_DEADLINE'
    assert failure['phase'] == 'final_live_check' and failure['marks'][4]
    unknown_slots = []
    safe_service_failures = []
    for control in artifact['controls']:
        for index, current in enumerate(control['snapshots']):
            for slot in ('last_failure', 'last_service_failure', 'last_tcp_failure'):
                value = current['metadata'].get(slot)
                if value is None:
                    continue
                item = {'label': control['label'], 'snapshot': index, 'slot': slot, **value}
                error = value['error']
                if error.get('code') is None and error.get('raw_os_error') is None and error.get('sqlite_extended_code') is None:
                    unknown_slots.append(item)
                if slot == 'last_service_failure':
                    safe_service_failures.append(item)
    summary['lanes'].append({
        'lane': artifact['lane'], 'artifact_id': artifact['artifact_id'],
        'archive_bytes': artifact['archive_bytes'], 'archive_sha256': artifact['archive_sha256'],
        'tested_commit': artifact['tested_commit'], 'passed_controls': 43,
        'diagnostic_snapshot_count': artifact['diagnostic_snapshot_count'],
        'controls_without_diagnostics': artifact['controls_without_diagnostics'],
        'diagnostic_quality': artifact['diagnostic_quality'],
        'native31': {
            'last_failure': failure,
            'records_overwritten': snapshot['metadata']['records_overwritten'],
            'retained_record_ids': snapshot['retained_record_ids'],
            'selected_phase_statistics': {
                name: snapshot['phase_statistics'][name] for name in phase_names
            },
        },
        'unknown_failure_slots': unknown_slots,
        'safe_service_failure_slots': safe_service_failures,
    })

for name, value in [('pq-controls-phase-analysis.json', report), ('pq-controls-phase-summary.json', summary)]:
    content = (json.dumps(value, indent=2) + '\n').encode()
    path = BASE / name
    atomic(path, content)
    print(json.dumps({'path': str(path), 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}))
print(json.dumps({
    'validated_controls': 172,
    'lanes': [{
        'lane': lane['lane'],
        'snapshots': lane['diagnostic_snapshot_count'],
        'unknown_slots': [{
            'label': item['label'], 'slot': item['slot'], 'phase': item['phase'],
            'code': item['error']['code']
        } for item in lane['unknown_failure_slots']],
        'native31_failure_wall_ms': lane['native31']['last_failure']['wall_ns'] / 1e6,
        'native31_failure_cpu_ms': lane['native31']['last_failure']['thread_cpu_ns'] / 1e6,
    } for lane in summary['lanes']],
}, separators=(',', ':')))

