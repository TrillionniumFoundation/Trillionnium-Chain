#!/usr/bin/env python3
"""Independent postcleanup observation and lossless evidence archive; no jobs launched."""
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def ticks(pid):
    try:
        raw = (Path('/proc') / str(pid) / 'stat').read_text()
        return int(raw[raw.rfind(')') + 2:].split()[19])
    except (FileNotFoundError, ProcessLookupError):
        return None


def main():
    campaign = ROOT / 'campaign-01'
    result = json.loads((campaign / 'result.json').read_text())
    manifest = json.loads((ROOT / 'inputs/manifest.json').read_text())
    unit = result['unit']
    cgroup = Path(result['cgroup_before']['path'])
    query = subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState',
        '--property=ActiveState', '--property=SubState', '--property=ControlGroup', '--property=MainPID'],
        capture_output=True, text=True)
    identities = []
    for row in result['requests']:
        if not row['spawned']:
            continue
        previous = row.get('membership_before_release', {}).get('starttime_ticks')
        current = ticks(row['pid'])
        identities.append({'ordinal': row['ordinal'], 'pid': row['pid'],
                           'original_starttime_ticks': previous, 'current_starttime_ticks': current,
                           'same_process_still_present': previous is not None and current == previous})
    active = []
    expected = str(ROOT / 'inputs/node-adapter')
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            if os.readlink(path / 'exe') == expected:
                active.append(int(path.name))
        except OSError:
            pass
    origin_after = {}
    for name, pin in manifest['origin_files'].items():
        path = Path(name)
        try:
            digest = sha(path)
            origin_after[name] = {'exists': True, 'bytes': path.stat().st_size,
                                  'sha256': digest, 'unchanged': digest == pin['sha256']}
        except OSError as error:
            origin_after[name] = {'exists': False, 'error': str(error), 'unchanged': False}
    copied_after = {name: sha(ROOT / 'inputs' / name) == pin['sha256'] for name, pin in manifest['files'].items()}
    observations = []
    for row in result['requests']:
        request = Path(row['request_output']) if row.get('request_output') else None
        receiver = request / 'receiver-node' if request else None
        observations.append({'ordinal': row['ordinal'], 'kind': row['kind'], 'case': row['case'],
                             'request_output': str(request) if request else None,
                             'request_output_exists': request.exists() if request else False,
                             'receiver_node_exists': receiver.exists() if receiver else False,
                             'receiver_node_files': [{'path': str(p.relative_to(receiver)), 'bytes': p.stat().st_size,
                                                     'sha256': sha(p)} for p in sorted(receiver.rglob('*')) if p.is_file()]
                                                    if receiver and receiver.is_dir() else [],
                             'exercise_receipt_exists': (request / 'exercise.json').is_file() if request else False,
                             'node_opened_reported': row.get('node_opened_reported')})
    files = {}
    if cgroup.exists():
        for name in ('cgroup.procs', 'cgroup.events', 'memory.events', 'pids.events', 'cpu.stat'):
            try:
                files[name] = (cgroup / name).read_text().strip()
            except OSError as error:
                files[name] = {'error': str(error)}
    empty = not cgroup.exists() or (files.get('cgroup.procs') == '' and isinstance(files.get('cgroup.events'), str)
                                  and 'populated 0' in files['cgroup.events'].splitlines())
    value = {'schema': 'w1-node-pressure-independent-postcleanup-v1',
             'observed_utc': datetime.now(timezone.utc).isoformat(), 'monotonic_ns': time.monotonic_ns(),
             'unit': unit, 'query_exit_code': query.returncode, 'query_stdout': query.stdout, 'query_stderr': query.stderr,
             'cgroup_path': str(cgroup), 'cgroup_exists': cgroup.exists(), 'cgroup_files': files,
             'known_pid_identities': identities, 'active_exact_adapter_copy_pids': active,
             'result_sha256': sha(campaign / 'result.json'), 'input_manifest_sha256': sha(ROOT / 'inputs/manifest.json'),
             'manifest_unchanged': sha(ROOT / 'inputs/manifest.json') == result['input_manifest_sha256'],
             'origin_files_after': origin_after, 'original_source_binaries_inputs_unchanged': all(v['unchanged'] for v in origin_after.values()),
             'copied_files_unchanged': copied_after, 'all_copied_files_unchanged': all(copied_after.values()),
             'source_head_after': subprocess.check_output(['git', '-C', manifest['source_repository'], 'rev-parse', 'HEAD'], text=True).strip(),
             'request_stores': observations,
             'cleanup_confirmed': empty and not any(v['same_process_still_present'] for v in identities) and not active,
             'observation_is_after_four_second_budget': True,
             'missing_receipt_is_not_node_opened_false': True, 'qualification': 'HOLD_NO_GO'}
    save(ROOT / 'independent_cleanup.json', value)
    for key in ('cleanup_confirmed', 'original_source_binaries_inputs_unchanged', 'all_copied_files_unchanged', 'manifest_unchanged'):
        if value[key] is not True:
            raise RuntimeError('POSTRUN_CONTROL_FAILED:' + key)
    # Preserve every original byte in logs/receipts/scripts/source snapshots. Raw
    # executables/proofs and any SQLite store remain at their pinned remote paths.
    included = []
    omitted = {}
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if '__pycache__' in path.parts or relative.endswith('.tar.gz') or relative == 'evidence-files.json':
            continue
        if (relative in ('inputs/node-adapter', 'inputs/mutate_last_query') or relative.endswith('.bin')
                or 'receiver-node' in path.parts):
            omitted[relative] = {'bytes': path.stat().st_size, 'sha256': sha(path), 'retained_remote': str(path)}
            continue
        included.append(path)
    inventory = {'schema': 'w1-node-pressure-evidence-inventory-v1',
                 'included': {p.relative_to(ROOT).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in included},
                 'binary_and_database_files_retained_remote': omitted,
                 'metadata_archive_is_lossless_for_all_included_files': True}
    save(ROOT / 'evidence-files.json', inventory)
    included.append(ROOT / 'evidence-files.json')
    archive = ROOT / 'node-pressure-evidence.tar.gz'
    with archive.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for path in sorted(included):
                    info = tar.gettarinfo(str(path), arcname=path.relative_to(ROOT).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 0
                    with path.open('rb') as stream:
                        tar.addfile(info, stream)
    receipt = {'result': 'PASS', 'campaign_summary': result['summary'],
               'cleanup_confirmed': value['cleanup_confirmed'], 'source_binaries_inputs_unchanged': True,
               'archive': str(archive), 'bytes': archive.stat().st_size, 'sha256': sha(archive),
               'archived_files': len(included), 'binary_database_files_retained_remote': len(omitted),
               'new_complete_proofs': 0, 'qualification': 'HOLD_NO_GO'}
    save(ROOT / 'archive.json', receipt)
    print(json.dumps(receipt, indent=2), flush=True)


if __name__ == '__main__':
    main()
