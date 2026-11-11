#!/usr/bin/env python3
"""Independent, fail-closed readback of an ORIGINAL PQ Root/PoN campaign ZIP.

This only authenticates and interprets retained repository/runner evidence.
It cannot prove independent custody, anti-rollback freshness, payment finality,
cryptographic bounds, or a production qualification. In particular, repeated
fixed-fixture confirmations must never be called unique paid business effects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import PurePosixPath
import stat
import sys
import zipfile

EXPECTED_INPUTS = {
    'attacker_processes': [0, 24, 24], 'business_blocks': 21,
    'modes': ['baseline', 'from-zero', 'late-product'],
    'phase_seconds': 30, 'seed_blocks': 4, 'seed_transfers': 1024,
}
FIXED_LIMITS = {
    'cpu.max': '25000 100000', 'cpu.max.burst': '0',
    'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256',
}
FIXED_PARENT = '/sys/fs/cgroup/trnmponpublic.slice'
MAX_FILES = 20000
MAX_PAYLOAD_BYTES = 4 << 30
MAX_JSON_BYTES = 100 << 20


class EvidenceError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise EvidenceError(message)


def json_member(z: zipfile.ZipFile, name: str):
    meta = z.getinfo(name)
    require(meta.file_size <= MAX_JSON_BYTES, f'JSON_TOO_LARGE: {name}')
    return json.loads(z.read(name))


def verify_zip(z: zipfile.ZipFile) -> dict:
    entries = z.infolist()
    names = [x.filename for x in entries]
    require(len(names) == len(set(names)), 'DUPLICATE_MEMBER')
    require(1 < len(names) <= MAX_FILES, 'MEMBER_COUNT')
    for e in entries:
        path = PurePosixPath(e.filename)
        require(not e.is_dir() and not path.is_absolute() and
                path.as_posix() == e.filename and '..' not in path.parts and
                '\\' not in e.filename and '\x00' not in e.filename and
                all(p not in ('', '.') for p in path.parts),
                f'UNSAFE_MEMBER: {e.filename}')
        require(not e.flag_bits & 1, f'ENCRYPTED_MEMBER: {e.filename}')
        mode = e.external_attr >> 16
        require(not mode or stat.S_IFMT(mode) in (0, stat.S_IFREG),
                f'NONREGULAR_MEMBER: {e.filename}')
    require('artifact-files.json' in names, 'MISSING_MANIFEST')
    manifest = json_member(z, 'artifact-files.json')
    files = manifest['files']
    require(type(files) is list and len(files) == len(names) - 1,
            'MANIFEST_MEMBER_COUNT')
    expected = {}
    for entry in files:
        require(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'},
                'INVALID_MANIFEST_ENTRY')
        path, size, digest = entry['path'], entry['bytes'], entry['sha256']
        require(type(path) is str and path not in expected and
                type(size) is int and size >= 0 and
                type(digest) is str and len(digest) == 64 and
                all(c in '0123456789abcdef' for c in digest),
                'INVALID_MANIFEST_VALUE')
        expected[path] = (size, digest)
    require(set(names) == set(expected) | {'artifact-files.json'},
            'MANIFEST_ENTRY_SET_MISMATCH')
    require(sum(s for s, _ in expected.values()) <= MAX_PAYLOAD_BYTES,
            'PAYLOAD_TOO_LARGE')
    total = 0
    for name, (size, want_digest) in expected.items():
        info = z.getinfo(name)
        require(info.file_size == size, f'MANIFEST_SIZE_MISMATCH: {name}')
        digest = hashlib.sha256()
        actual_size = 0
        # Streaming read checks the decompression CRC via zipfile on EOF.
        with z.open(name) as inp:
            for chunk in iter(lambda: inp.read(1 << 20), b''):
                digest.update(chunk)
                actual_size += len(chunk)
        require(actual_size == size and digest.hexdigest() == want_digest,
                f'MANIFEST_DIGEST_MISMATCH: {name}')
        total += actual_size
    return {'manifest_payload_entries': len(expected),
            'manifest_payload_bytes': total, 'zip_members': len(entries)}


def summarize(results: dict, reports: list[dict], host_before: list[dict]) -> dict:
    """Pure reporting, independently testable without large fixture files."""
    require(results['original_inputs'] == EXPECTED_INPUTS, 'ORIGINAL_WORKLOAD_CHANGED')
    placement = results['public_phase_placement']
    require(placement['receiver_and_verifier_cpu_max'] == FIXED_LIMITS['cpu.max']
            and placement['receiver_and_verifier_memory_max'] == FIXED_LIMITS['memory.max']
            and placement['fixed_parent'] == FIXED_PARENT
            and placement['original_3x3_workload_and_depletion_predicates_changed'] is False,
            'PUBLIC_PHASE_RESOURCE_CONTRACT_CHANGED')
    attempts = results['attempts']
    require(len(attempts) == 3 and [a['number'] for a in attempts] == [1, 2, 3],
            'ORIGINAL_THREE_RUN_DENOMINATOR_CHANGED')
    require(len(reports) == 3 and len(host_before) == 9,
            'NINE_PHASE_EVIDENCE_REQUIRED')
    for h in host_before:
        require(h['limits'] == FIXED_LIMITS and h['parent_path'] == FIXED_PARENT
                and h['parent']['canonical_path'] == FIXED_PARENT
                and h['parent']['uid'] == 0 and h['parent']['directory'] is True
                and h['parent']['symlink'] is False and h['read_errors'] == {},
                'HOST_LIMITS_OR_PARENT_FAILED')
    phases = []
    observed_confirmations = []
    history_rpc_ok = history_import_ok = history_import_failed = 0
    for run_number, report in enumerate(reports, 1):
        run_phases = report['phases']
        require(len(run_phases) == 3 and
                [p['mode'] for p in run_phases] == EXPECTED_INPUTS['modes'],
                'PHASE_DENOMINATOR_OR_ORDER_CHANGED')
        for index, p in enumerate(run_phases):
            mode = EXPECTED_INPUTS['modes'][index]
            require(p['duration_seconds'] == 30 and
                    p['attacker_processes_requested'] == EXPECTED_INPUTS['attacker_processes'][index],
                    'ORIGINAL_PHASE_WORKLOAD_CHANGED')
            n_window = 0
            for c in p['confirmations']:
                if c['confirmed_inside_pressure_window'] is True:
                    observation = c.get('observation')
                    require(type(observation) is dict and observation['confirmed'] is True
                            and type(c.get('ended_ns')) is int and c['ended_ns'] <= 30_000_000_000,
                            'INCONSISTENT_WINDOW_CONFIRMATION')
                    tx = c.get('transaction')
                    require(type(tx) is str and tx and observation['transaction'] == tx,
                            'CONFIRMATION_TRANSACTION_IDENTITY_MISSING')
                    observed_confirmations.append({
                        'run': run_number, 'mode': mode, 'round': c['round'],
                        'transaction': tx, 'included_block': c.get('included_block'),
                        'finalized': observation.get('finalized'),
                        'execution_authority': observation.get('execution_authority'),
                    })
                    n_window += 1
            for h in p['history']:
                rpc_ok = h.get('status') == 'ok' and h.get('response', {}).get('ok') is True
                if rpc_ok:
                    history_rpc_ok += 1
                imp = h.get('client_import')
                if imp is not None:
                    if imp.get('succeeded') is True:
                        require(rpc_ok, 'CLIENT_IMPORT_SUCCEEDED_WITHOUT_RPC')
                        history_import_ok += 1
                    elif imp.get('succeeded') is False:
                        history_import_failed += 1
                    else:
                        raise EvidenceError('UNCLASSIFIED_CLIENT_IMPORT')
            if p['finite_phase_criteria_met'] is True:
                require(n_window == 3 and p['all_signed_rounds_confirmed_in_window'] is True
                        and p['receiver_client_state_equal'] is True
                        and p['observer_complete'] is True,
                        'CLAIMED_PHASE_PASS_WITHOUT_REQUIRED_CONFIRMED_STATE')
            phases.append({
                'run': run_number, 'mode': mode,
                'attacker_processes_requested': p['attacker_processes_requested'],
                'in_window_confirmations': n_window, 'planned_confirmations': 3,
                'phase_criteria_met': p['finite_phase_criteria_met'] is True,
                'receiver_client_state_equal': p['receiver_client_state_equal'] is True,
                'budget_depletion_observed': p['genuine_budget_depletion_observed'] is True,
            })
    for i, attempt in enumerate(attempts):
        if attempt['complete_success'] is True or attempt['original_criteria_met'] is True:
            require(attempt['complete_success'] is True and
                    attempt['original_criteria_met'] is True and
                    attempt['step']['returncode'] == 0 and
                    all(p['phase_criteria_met'] for p in phases[i * 3:(i + 1) * 3]),
                    'CLAIMED_CAMPAIGN_PASS_WITHOUT_THREE_PHASES')
    complete_campaigns = sum(a['complete_success'] is True and
                             a['original_criteria_met'] is True and
                             a['step']['returncode'] == 0 for a in attempts)
    # These are fixed test-fixture observations across runs, not distinct paid effects.
    distinct_transactions = sorted({c['transaction'] for c in observed_confirmations})
    return {
        'status': 'HOLD_NO_GO', 'production_activation': False,
        'actual_lifetime_failure_bound': None,
        'complete_original_campaigns': complete_campaigns,
        'planned_original_campaigns': 3,
        'complete_phases': sum(p['phase_criteria_met'] for p in phases),
        'planned_phases': 9,
        'window_confirmations': len(observed_confirmations),
        'planned_window_confirmations': 27,
        'receiver_client_equal_phases': sum(p['receiver_client_state_equal'] for p in phases),
        'history_rpc_ok': history_rpc_ok,
        'history_import_succeeded': history_import_ok,
        'history_import_failed': history_import_failed,
        'observed_window_transaction_ids': distinct_transactions,
        'distinct_fixture_transactions': len(distinct_transactions),
        'all_observed_window_confirmations_have_finality': all(
            c['finalized'] is True for c in observed_confirmations) and bool(observed_confirmations),
        'all_observed_window_confirmations_have_execution_authority': all(
            c['execution_authority'] is True for c in observed_confirmations) and bool(observed_confirmations),
        'phases': phases,
        'scope': 'Original native same-host evidence readback only: not independent real effects, WAN, custody or formal security bound',
    }


def audit(path: str, expected_head: str, expected_tree: str,
          expected_artifact_sha256: str) -> dict:
    require(len(expected_head) == 40 and len(expected_tree) == 40 and
            all(c in '0123456789abcdef' for c in expected_head + expected_tree),
            'EXPECTED_SOURCE_IDENTITY_REQUIRED')
    require(len(expected_artifact_sha256) == 64 and
            all(c in '0123456789abcdef' for c in expected_artifact_sha256),
            'EXPECTED_ARCHIVE_DIGEST_REQUIRED')
    archive_digest = hashlib.sha256()
    with open(path, 'rb') as inp:
        for chunk in iter(lambda: inp.read(1 << 20), b''):
            archive_digest.update(chunk)
    require(archive_digest.hexdigest() == expected_artifact_sha256,
            'ORIGINAL_ACTIONS_ARCHIVE_SHA_MISMATCH')
    with zipfile.ZipFile(path) as z:
        integrity = verify_zip(z)
        result = json_member(z, 'results.json')
        require(result['expected_head'] == expected_head and result['expected_tree'] == expected_tree,
                'SOURCE_HEAD_OR_TREE_MISMATCH')
        require(result['source_after']['tested_commit'] == expected_head and
                result['source_after']['tested_tree'] == expected_tree,
                'SOURCE_AFTER_MISMATCH')
        for snapshot in ('source-before.json', 'source-before-campaigns.json', 'source-after.json'):
            s = json_member(z, snapshot)
            require(s == result['source_after'] and s['kind'] == 'head' and
                    s['tracked_worktree_verified'] is True,
                    'SOURCE_BEFORE_AFTER_MISMATCH')
        require(result['binary']['sha256_after'] == result['binary']['sha256_before'],
                'TEST_BINARY_CHANGED')
        reports = []
        hosts = []
        for n, attempt in enumerate(result['attempts'], 1):
            report_path = f'run-{n}-raw/report.json'
            require(z.getinfo(report_path).file_size <= MAX_JSON_BYTES,
                    'REPORT_TOO_LARGE')
            raw_report = z.read(report_path)
            require(hashlib.sha256(raw_report).hexdigest() == attempt['report_sha256'],
                    'REPORT_SHA_MISMATCH')
            reports.append(json.loads(raw_report))
            for mode in EXPECTED_INPUTS['modes']:
                hosts.append(json_member(
                    z, f'run-{n}-raw/{mode}-host-control/host/inside-before.json'))
        observation = summarize(result, reports, hosts)
        return {'schema': 'pq-root-native-independent-readback-v1',
                'artifact_sha256': archive_digest.hexdigest(),
                'source_head': expected_head, 'source_tree': expected_tree,
                **integrity, **observation}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('zip', help='Unmodified original GitHub Actions ZIP')
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--expected-artifact-sha256', required=True,
                        help='Digest from the original Actions upload log, not the ZIP itself')
    args = parser.parse_args()
    try:
        report = audit(args.zip, args.expected_head, args.expected_tree,
                       args.expected_artifact_sha256)
    except (EvidenceError, KeyError, IndexError, TypeError, ValueError,
            zipfile.BadZipFile, OSError) as error:
        print(json.dumps({'status': 'REFUSED', 'error': str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
