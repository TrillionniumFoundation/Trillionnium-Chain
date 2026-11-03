#!/usr/bin/env python3
"""Audit the original PQ5 #548 artifact without executing its native binaries.

Requires Python 3.10+ and the source snapshot at
6cd321a6e5f36dabec60e5e234294c4167330476. No Cargo toolchain, network, Git
checkout metadata, or installed third-party Python packages are required.
The source dependency is 34 distinct manifest-pinned inputs, plus two pinned
support modules imported by the original readers. A full exact-head source
checkout supplies these; this script does not copy or modify that checkout.

Example:
    python -B audit_artifact.py --archive /path/to/original.zip \
        --sources-root /path/to/exact-head-source --output /path/to/audit.json
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
HEAD = '6cd321a6e5f36dabec60e5e234294c4167330476'
TREE = '60fef042f4fabb017bbbd33760ac428bb3e39592'
HOSTED_ROOT = '/home/runner/work/Trillionnium-Chain/Trillionnium-Chain'
ZIP_SHA = 'eaa76bb9a422bf76301ef8215d2d78baf85b184c0f12161c0ab1b815010f4cc8'
SUPPORT_INPUTS = {
    'scripts/ci/ci_observation.py': '389154c792fd3c734621278fb4188e9863ff599efb0c9b863316f540a94eab4a',
    'formal/pon-nakamoto-v1/bounded_process.py': 'da175430a6b669d3e7d40fe7ec0e7bc00fe6e992cc2d4d443af07209b4013815',
}
parser = argparse.ArgumentParser(
    description=__doc__, allow_abbrev=False,
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument('--archive', type=Path,
                    default=HERE / 'native-pq5-12887549582.zip',
                    help='Original artifact 12887549582 ZIP; its fixed size and SHA256 are checked')
parser.add_argument('--sources-root', type=Path, default=HERE.parent / 'repo',
                    help='Exact-head source root with 34 manifest inputs and two reader support modules')
parser.add_argument('--output', type=Path, default=HERE / 'artifact-audit.json',
                    help='Destination for the independently recomputed audit JSON')
args = parser.parse_args()
ROOT = args.sources_root.resolve()
ARCHIVE = args.archive.resolve()
OUTPUT = args.output.resolve()
sys.dont_write_bytecode = True


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


archive = ARCHIVE.read_bytes()
require(len(archive) == 7922096 and sha(archive) == ZIP_SHA, 'GitHub archive identity')
with zipfile.ZipFile(ARCHIVE) as z:
    infos = z.infolist()
    require(len(infos) == 38 and len({i.filename for i in infos}) == 38, 'archive roster')
    for info in infos:
        path = PurePosixPath(info.filename)
        require(not path.is_absolute() and '..' not in path.parts and not info.is_dir(), 'archive path')
        require((info.external_attr >> 16) & 0o170000 != 0o120000, 'archive symlink')
    # Reading every member also verifies every original ZIP CRC.
    content = {info.filename: z.read(info) for info in infos}


def text(name: str) -> str:
    return content[name].decode('utf-8')


def doc(name: str):
    return json.loads(content[name])


source_before = doc('source-before.json')
source_after = doc('source-after.json')
require(source_before == source_after, 'source before/after differs')
require(source_before['schema'] == 'trnm-ci-source-v1'
        and source_before['kind'] == 'head'
        and source_before['candidate'] == HEAD
        and source_before['tested_commit'] == HEAD
        and source_before['tested_tree'] == TREE
        and source_before['tracked_worktree_verified'] is True
        and source_before['tracked_entries'] == 6055
        and source_before['tracked_bytes'] == 798929412
        and source_before['tests_executed_by_identity_check'] is False, 'source identity guard')
require(doc('source-guard-before.log') == source_before
        and doc('source-guard-after.log') == source_after, 'source guard log/receipt')

base = doc('run/manifest.json')
anchored = doc('anchored-migration/manifest.json')
require(base['schema'] == 'native-pq-tasks-v5-research-ci-v1', 'original baseline schema')
require(anchored['schema'] == 'native-pq5-anchored-migration-research-ci-v1', 'anchored schema')
source = {'commit': HEAD, 'tree': TREE, 'source_state': 'committed-clean',
          'tracked_bytes': 798929412, 'tracked_entries': 6055, 'tracked_worktree_verified': True}
for report in (base, anchored):
    require(report['result'] == 'PASS' and report['source_expected'] == HEAD
            and report['source_consistent'] is True and report['source'] == source, 'report source/result')
    require(report['production_activation'] is False
            and report['whole_chain_post_quantum'] is False, 'qualification scope')

# Verify the relocated source inputs before importing the original read-only
# parsers. The two transitive support modules are not manifest input pins, so
# their exact-head SHA256 values are pinned separately above.
for report in (base, anchored):
    for name, digest in report['input_sha256'].items():
        require(sha((ROOT / name).read_bytes()) == digest, 'pre-import source input: ' + name)
for name, digest in SUPPORT_INPUTS.items():
    require(sha((ROOT / name).read_bytes()) == digest, 'pre-import support input: ' + name)
sys.path.insert(0, str(ROOT / 'scripts/ci'))
import read_native_pq_tasks_v5_migration_v1 as reader
import run_native_pq_tasks_v5_migration_v1 as migration

require(set(base['input_sha256']) == reader.baseline_inputs(ROOT), 'original input roster')
require(set(anchored['input_sha256']) == set(migration.INPUTS), 'migration input roster')
artifact_pins = []
input_pins = []
for prefix, report in [('run', base), ('anchored-migration', anchored)]:
    for name, digest in report['artifact_sha256'].items():
        full = prefix + '/' + name
        require(sha(content[full]) == digest, 'artifact pin: ' + full)
        artifact_pins.append(full)
    for name, digest in report['input_sha256'].items():
        require(sha((ROOT / name).read_bytes()) == digest, 'frozen source input pin: ' + name)
        input_pins.append(name)
require(len(artifact_pins) == 26 and len(input_pins) == 38, 'pin counts')

expected_migration_command = ['cargo', '+1.95.0', 'test', '--locked', '--manifest-path',
                              'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test',
                              'native_pq_tasks_v5_migration_v1', '--', '--show-output', '--test-threads=1']
commands = [('run', base, reader.baseline_commands(), 2400),
            ('anchored-migration', anchored, [('native-migration.log', expected_migration_command)], 900)]
for prefix, report, expected, budget in commands:
    require(len(report['observations']) == len(expected), 'all commands present')
    require(report['total_command_budget_seconds'] == budget, 'original time budget')
    for obs, (log, command) in zip(report['observations'], expected, strict=True):
        require(obs['command'] == command and obs['log'] == log and log in report['artifact_sha256']
                and obs['cwd'] == HOSTED_ROOT and obs['expected_source'] == HEAD
                and obs['exit_code'] == 0 and obs['process_exit_code'] == 0
                and obs['executed'] is True and obs['timed_out'] is False
                and obs['source_before_verified'] is True and obs['source_after_verified'] is True
                and obs['source_verified'] is True and not obs.get('source_error')
                and type(obs['elapsed_ns']) is int and obs['elapsed_ns'] > 0,
                'command execution/source guard: ' + log)
    require(sum(o['elapsed_ns'] for o in report['observations']) <= budget * 1_000_000_000,
            'command elapsed budget')
require('\nrelease: 1.95.0\n' in '\n' + text('run/rustc.log'), 'actual compiler release')
require('rustc 1.95.0 (59807616e 2026-04-14)' in text('rustup.log'), 'installed compiler')

parsed = {}
for name, _, _, required in reader.BASE_TESTS:
    raw = text('run/' + name + '.log')
    parsed[name] = (reader.retained.unit_result(raw, name) if required is None
                    else reader.retained.test_result(raw, required, exact=True))
require(parsed == base['tests'], 'complete raw test/manifest match')
require(sum(r['passed'] for r in parsed.values()) == 205, '205 executed tests')
require(sum(r['ignored'] for r in parsed.values()) == 8, 'original eight ignores only')
require(all(r['failed'] == r['filtered_out'] == r['measured'] == 0 for r in parsed.values()), 'zero failures/filters')
require(sum(parsed[name]['passed'] for name, _, _, required in reader.BASE_TESTS if required is not None) == 68,
        '68 integration tests')
regression = 'pon_executor::pq_accounts_v2::tests::anchored_migration_conserves_all_accounts_tasks_rewards_and_claims_once'
require(parsed['m06']['test_outcomes'][regression] == 'ok', 'claimed-nonce regression executed')

phases = {
    'native-task-phases.json': reader.retained.task_phases(text('run/native-task.log')),
    'retained-task-phases.json': reader.retained.v4_task_phases(text('run/retained-native-task.log')),
    'retained-quota-phases.json': reader.retained.quota_phases(text('run/retained-native-quota.log')),
    'retained-pq2-phases.json': reader.retained.phase_result(text('run/retained-pq2.log')),
}
for name, rows in phases.items():
    require(doc('run/' + name) == rows, 'raw phases: ' + name)
require(base['native_task_phase_count'] == 37, 'original native task phases')
native = reader.native_result(text('anchored-migration/native-migration.log'))
require(native == anchored['native'] == doc('anchored-migration/native-observed.json'), 'raw anchored native observations')
require(native['tests']['passed'] == 3
        and native['tests']['failed'] == native['tests']['ignored'] == native['tests']['filtered_out'] == 0,
        'three executed anchored tests')

binaries = []
for prefix, report, logfile in [('run', base, 'native-task.log'),
                              ('anchored-migration', anchored, 'native-migration.log')]:
    binary = report['native_binary']
    member = prefix + '/' + binary['retained_gzip']
    compressed = content[member]
    raw = gzip.decompress(compressed)
    require(sha(compressed) == binary['gzip_sha256'] == report['artifact_sha256'][binary['retained_gzip']], 'gzip pin')
    require(len(raw) == binary['bytes'] and sha(raw) == binary['sha256'], 'ELF byte identity')
    require(raw.startswith(b'\x7fELF\x02\x01') and struct.unpack('<H', raw[18:20])[0] == 62, 'x86_64 ELF')
    running = re.findall(r'Running .*\(([^)]+)\)', text(prefix + '/' + logfile))
    require(running == [binary['cargo_path']], 'raw executed ELF path')
    binaries.append({'member': member, 'elf_bytes': len(raw), 'elf_sha256': sha(raw),
                     'gzip_sha256': sha(compressed), 'raw_running_path_matches': True,
                     'format': 'ELF64 little-endian x86-64'})

expected_retained = {'source_commit': HEAD, 'source_tree': TREE, 'passed': 205,
    'integration_passed': 68, 'original_ignored': 8, 'executed_commands': 18,
    'native_task_phases': 37, 'manifest_sha256': sha(content['run/manifest.json']),
    'native_binary_sha256': base['native_binary']['sha256'], 'historical_report_flags_rewritten': False}
require(anchored['retained_205'] == expected_retained, 'cross-bound original retained receipt')
require(anchored['p1_scoped_shared_profile_qualified'] is True
        and anchored['prior_pq_registry_is_external_assumption'] is True
        and anchored['source_chain_retirement_proved'] is False
        and anchored['old_store_upgraded'] is False
        and base['p1_complete'] is False, 'explicit remaining boundaries')
python_checks = {}
for name, count in [('reader-negatives.log', 12), ('anchored-reader-negatives.log', 9),
                    ('run/source-negatives.log', 34)]:
    raw = text(name)
    require(re.search(rf'Ran {count} tests in ', raw) is not None
            and re.search(r'^OK$', raw, re.MULTILINE) is not None, 'negative-reader/source tests')
    python_checks[name] = count

audit = {
    'schema': 'pq548-hosted-artifact-independent-audit-v1', 'result': 'PASS',
    'method': 'Archive CRC/SHA and original read-only parsing functions; no binary re-execution',
    'run_id': 40852473308, 'job_id': 123375111992, 'artifact_id': 12887549582,
    'head': HEAD, 'tree': TREE, 'archive_bytes': len(archive), 'archive_sha256': ZIP_SHA,
    'archive_entries_read_and_crc_verified': len(content),
    'artifact_sha256_pins_checked': len(artifact_pins), 'input_sha256_pins_checked': len(input_pins),
    'unique_source_inputs_checked': len(set(input_pins)), 'source_guard': source_before,
    'guarded_commands': {'baseline': 18, 'anchored': 1}, 'rustc': text('run/rustc.log').strip(),
    'baseline_tests': {name: {k: row[k] for k in ('passed','failed','ignored','filtered_out','measured')}
                       for name, row in parsed.items()},
    'baseline_total_passed': 205, 'integration_passed': 68,
    'original_ignored_names': {name: [n for n,s in row['test_outcomes'].items() if s == 'ignored']
                              for name,row in parsed.items() if row['ignored']},
    'changed_regression_test': regression, 'changed_regression_result': 'ok',
    'phase_counts': {name: len(rows) for name,rows in phases.items()},
    'anchored_tests': native['tests'], 'anchored_phase_count': len(native['phases']),
    'anchored_completions': native['completions'], 'python_checks': python_checks,
    'native_binaries': binaries, 'cross_bound_retained_205': expected_retained,
    'remaining_boundaries': {
        'production_activation': False, 'whole_chain_post_quantum': False,
        'p1_complete': False, 'prior_pq_registry_is_external_assumption': True,
        'source_chain_retirement_proved': False, 'old_store_upgraded': False,
        'shared_host_not_worst_case_cost': True, 'local_reexecution_of_hosted_binaries': False,
    },
    'archive_members_sha256': {name: sha(data) for name,data in content.items()},
}
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(audit, indent=2) + '\n')
print(json.dumps({k:v for k,v in audit.items() if k not in ('archive_members_sha256', 'anchored_completions')}))
