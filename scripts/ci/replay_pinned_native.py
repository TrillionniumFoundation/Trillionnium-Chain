#!/usr/bin/env python3
"""Replay retained native binaries, not a source build or a CI pass.

Linux wait4 measures one complete child at a time, including setup, misses,
verification, output serialization and process overhead. Never apportion that
CPU time to the native program's nested wall timers or call it a CPU ratio.
Archives require an independently supplied SHA-256 and exact source commit.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time
from typing import Any
import zipfile

COST_PROGRAMS = {
    'pon_reused_cost': 'cross-arch-cost',
    'pon_maintenance_cost': 'cross-arch-maintenance-cost',
    'pon_zero_locality_cost': 'cross-arch-zero-locality-cost',
    'pon_one_zero_locality_cost': 'cross-arch-one-zero-locality-cost',
    'pon_rejection_cost': 'work-rejection',
}
ARCHIVE_PROGRAMS = {
    'account_archive_vectors': 'account-archive',
    'account_execution_vectors': 'account-execution',
}
FALSE_FLAGS = ('fastest_adversary_qualified', 'work_hardness_accepted',
               'public_service_measured', 'production_activation')

def require(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_load(raw: bytes | str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def producer_observations(doc: dict[str, Any], expected_arms: dict[str, list[list[str]]],
                          expected_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    if expected_plan is not None:
        require(all(type(doc.get(k)) is type(v) and doc.get(k) == v
                    for k, v in expected_plan.items()), 'COMMAND_OUTPUT_MISMATCH')
    for flag in FALSE_FLAGS:
        require(doc.get(flag) is False, 'SCOPE_PROMOTION')
    for key in ('samples_per_case_target', 'searches_per_cohort', 'attempt_budget'):
        require(integer(doc.get(key)) and doc[key] > 0, 'ZERO_OR_INVALID_EXECUTION')
    require(integer(doc.get('seed')), 'INVALID_SEED')
    require(isinstance(doc.get('targets'), list) and len(doc['targets']) == 2
            and len(set(doc['targets'])) == 2, 'TARGET_INVENTORY')
    rows = doc.get('observations')
    require(isinstance(rows, list) and len(rows) > 0, 'ZERO_EXECUTION')
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    counts: Counter[str] = Counter()
    task_contexts: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
    for row in rows:
        key = (row['class'], row['task'], row['target'], row['sample'])
        groups[key].append(row)
        task_contexts[row['class']].add((row['task'], row['input_source'],
                                         row['rank_a'], row['rank_b']))
        require(all(integer(row[f]) and row[f] <= 64 for f in ('rank_a', 'rank_b')),
                'RANK_VALUES')
        require(row['class'] in expected_arms, 'UNEXPECTED_TASK_CLASS')
        require(row['target'] in doc['targets'] and integer(row['sample'])
                and row['sample'] < doc['samples_per_case_target'], 'COHORT_CONTEXT')
        require(re.fullmatch('[0-9a-f]{64}', row['task']) is not None, 'TASK_DIGEST')
        require(row['proof_bytes'] == 49188, 'PROOF_BYTES')
        setup = row['setup_observations_ns']
        require(isinstance(setup, list) and all(integer(n) for n in setup), 'SETUP_VALUES')
        require(integer(row['setup_calls']) and row['setup_calls'] == len(setup), 'SETUP_COUNT')
        require(row['setup_elapsed_ns'] == sum(setup), 'SETUP_SUM')
        for field in ('setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns', 'invocation_order'):
            require(integer(row[field]), 'COST_VALUES')
        require(row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'], 'COST_SUM')
        outcomes = row['outcomes']
        require(len(outcomes) == doc['searches_per_cohort'], 'MISSING_SEARCH')
        require(all(integer(o['search_index']) for o in outcomes)
                and [o['search_index'] for o in outcomes] == list(range(len(outcomes))), 'SEARCH_ORDER')
        require(row['search_elapsed_ns'] == sum(o['search_elapsed_ns'] for o in outcomes), 'SEARCH_SUM')
        expected_setup = 0 if row['strategy'] == 'scalar-original' else (
            doc['searches_per_cohort'] if row['mode'] == 'cold-per-search' else 1)
        require(row['setup_calls'] == expected_setup, 'SETUP_MODE')
        # Unsupported means actual constructor refusals, not omitted observations.
        if row['method'] == 'unsupported':
            require(row['search_elapsed_ns'] == 0, 'UNSUPPORTED_SEARCH')
            for item in outcomes:
                require(item['status'] == 'unsupported' and type(item['attempts']) is int
                        and item['attempts'] == 0 and item['search_elapsed_ns'] == 0,
                        'UNSUPPORTED_OUTCOME')
                require(all(item[field] is None for field in (
                    'ticket_stream_commitment', 'proof_stream_commitment',
                    'winning_challenge', 'winner_proof_commitment',
                    'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                    'reference_verifier_first')), 'UNSUPPORTED_PROOF')
            counts['unsupported_arms'] += 1
            counts['unsupported'] += len(outcomes)
            continue
        for item in outcomes:
            require(integer(item['attempts']) and 0 < item['attempts'] <= doc['attempt_budget'], 'ATTEMPT_DENOMINATOR')
            require(integer(item['search_elapsed_ns']), 'SEARCH_COST')
            for field in ('ticket_stream_commitment', 'proof_stream_commitment'):
                require(isinstance(item[field], str) and re.fullmatch('[0-9a-f]{64}', item[field]) is not None, 'STREAM_COMMITMENT')
            if item['status'] == 'exhausted':
                require(item['attempts'] == doc['attempt_budget'], 'EXHAUSTION_COUNT')
                require(all(item[field] is None for field in (
                    'winning_challenge', 'winner_proof_commitment',
                    'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                    'reference_verifier_first')), 'EXHAUSTION_WINNER')
            else:
                require(item['status'] == 'winner', 'SEARCH_STATUS')
                for field in ('winning_challenge', 'winner_proof_commitment'):
                    require(isinstance(item[field], str) and re.fullmatch('[0-9a-f]{64}', item[field]) is not None, 'WINNER_COMMITMENT')
                require(integer(item['production_verifier_elapsed_ns'])
                        and integer(item['reference_verifier_elapsed_ns']), 'VERIFIER_TIME')
                require(type(item['reference_verifier_first']) is bool, 'VERIFIER_ORDER')
            counts[item['status']] += 1
            counts['attempts'] += item['attempts']
    require(all(len(values) == 1 for values in task_contexts.values()), 'TASK_CONTEXT_DRIFT')
    expected_classes = set(expected_arms)
    require({key[0] for key in groups} == expected_classes, 'MISSING_TASK_CLASS')
    for cls in expected_classes:
        contexts = {(key[2], key[3]) for key in groups if key[0] == cls}
        expected_contexts = {(target, sample) for target in doc['targets']
                             for sample in range(doc['samples_per_case_target'])}
        require(contexts == expected_contexts, 'MISSING_COHORT')
    deterministic = []
    for key, group in sorted(groups.items()):
        actual_arms = [(r['strategy'], r['mode']) for r in group]
        require(len(actual_arms) == len(set(actual_arms))
                and set(actual_arms) == {tuple(v) for v in expected_arms[key[0]]}, 'ARM_INVENTORY')
        require(sorted(r['invocation_order'] for r in group) == list(range(len(group))), 'INVOCATION_ORDER')
        comparable = [r for r in group if r['method'] != 'unsupported']
        require(bool(comparable), 'NO_SUPPORTED_ARM')
        def projection(row: dict[str, Any]) -> list[dict[str, Any]]:
            return [{k: v for k, v in o.items() if k not in (
                'search_elapsed_ns', 'production_verifier_elapsed_ns',
                'reference_verifier_elapsed_ns', 'reference_verifier_first')}
                    for o in row['outcomes']]
        reference = projection(comparable[0])
        require(all(projection(row) == reference for row in comparable), 'DIFFERENT_PROOF_OR_TICKET_STREAM')
        deterministic.append([list(key), reference])
    return {'rows': len(rows), 'cohorts': len(groups), **dict(counts),
            'deterministic_sha256': digest(json.dumps(deterministic, sort_keys=True).encode())}


def derive_arms(doc: dict[str, Any]) -> dict[str, list[list[str]]]:
    groups: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in doc['observations']:
        groups[row['class']].add((row['strategy'], row['mode']))
    return {key: [list(v) for v in sorted(values)] for key, values in sorted(groups.items())}


def validate_source_manifest(manifest: dict[str, Any], source: dict[str, Any]) -> None:
    # Older rejection receipts omit source_changed, but retain both full source
    # identities. Absence is not treated as false: compare the identities too.
    if 'source_changed' in manifest:
        require(manifest['source_changed'] is False, 'MANIFEST_SOURCE_CHANGED')
    require(manifest['source_before'] == manifest['source_after'], 'MANIFEST_SOURCE_DRIFT')
    for boundary in ('source_before', 'source_after'):
        identity = manifest[boundary]
        require(identity['commit'] == source['tested_commit']
                and identity['tree'] == source['tested_tree']
                and identity['tracked_worktree_verified'] is True, 'MANIFEST_SOURCE_BINDING')


def run_child(command: list[str], folder: Path, timeout: float = 90) -> dict[str, Any]:
    """Own and reap exactly this PID; preserve failed/timeout stdout and rusage."""
    folder.mkdir()
    start = time.monotonic_ns()
    timed_out = False
    with (folder/'stdout').open('xb') as stdout, (folder/'stderr').open('xb') as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        usage = None
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic_ns() - start > timeout * 1_000_000_000:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(0.005)
            process.returncode = os.waitstatus_to_exitcode(status)
        finally:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
    wall_ns = time.monotonic_ns() - start
    assert usage is not None
    cpu = lambda value: int((Decimal(str(value)) * 1_000_000).to_integral_value()) * 1000
    result = {'command': command, 'exit_code': process.returncode, 'timed_out': timed_out,
              'wall_ns': wall_ns, 'user_cpu_ns': cpu(usage.ru_utime),
              'system_cpu_ns': cpu(usage.ru_stime),
              'cpu_ns': cpu(usage.ru_utime) + cpu(usage.ru_stime),
              'max_rss_kib': usage.ru_maxrss,
              'rss_scope': 'whole waited child including pre-exec image; no Rust-only RSS attribution', 'minor_faults': usage.ru_minflt,
              'major_faults': usage.ru_majflt,
              'voluntary_switches': usage.ru_nvcsw, 'involuntary_switches': usage.ru_nivcsw,
              'cpu_scope': 'entire child, not apportioned to nested wall intervals',
              'wait4_cpu_resolution_ns': 1000,
              'stdout_sha256': digest((folder/'stdout').read_bytes()),
              'stderr_sha256': digest((folder/'stderr').read_bytes())}
    (folder/'process.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--only', action='append', choices=list(COST_PROGRAMS) + list(ARCHIVE_PROGRAMS))
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_X64_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', args.source) is not None, 'SOURCE_SHA')
    require(not args.archive.is_symlink(), 'SYMLINK_ARCHIVE')
    require(digest(args.archive.read_bytes()) == args.archive_sha256, 'ARCHIVE_DIGEST')
    args.output.mkdir()  # never reuse old run output
    (args.output/'bin').mkdir()
    receipt: dict[str, Any] = {'schema': 'trnm-pinned-native-replay-v1', 'source': args.source,
        'archive_sha256': args.archive_sha256, 'environment': {
            'uname': list(platform.uname()), 'cpu_affinity': sorted(os.sched_getaffinity(0)),
            'python': platform.python_version()}, 'source_recompiled': False,
        'new_rust_patch_executed': False, 'public_service_measured': False,
        'production_activation': False, 'runs': [], 'completed': False}
    try:
        with zipfile.ZipFile(args.archive) as archive:
            require(len(archive.namelist()) == len(set(archive.namelist())), 'DUPLICATE_ZIP_MEMBER')
            source = json_load(archive.read('source.json'))
            require(source['tested_commit'] == args.source and source['tracked_worktree_verified'] is True, 'SOURCE_BINDING')
            receipt['source_identity'] = source
            programs = COST_PROGRAMS if 'cross-arch-cost/manifest.json' in archive.namelist() else ARCHIVE_PROGRAMS
            if args.only:
                require(set(args.only) <= set(programs), 'PROGRAM_NOT_IN_ARCHIVE')
                require(len(args.only) == len(set(args.only)), 'DUPLICATE_PROGRAM')
                programs = {name: prefix for name, prefix in programs.items() if name in args.only}
            receipt['planned_programs'] = list(programs)
            for name, prefix in programs.items():
                manifest = json_load(archive.read(prefix+'/manifest.json'))
                validate_source_manifest(manifest, source)
                blob = archive.read(prefix+'/'+name)
                sha = digest(blob)
                require(sha == manifest['binary_sha256_before'] == manifest['binary_sha256_after'], 'BINARY_DIGEST')
                require(blob[:4] == b'\x7fELF' and blob[4:6] == bytes([2, 1])
                        and int.from_bytes(blob[18:20], 'little') == 62, 'ELF_ARCHITECTURE')
                binary = args.output/'bin'/name
                binary.write_bytes(blob); binary.chmod(0o700)
                (args.output/(name+'.original-manifest.json')).write_text(json.dumps(manifest, indent=2)+'\n')
                if name == 'pon_rejection_cost':
                    plans = [(0, [str(binary)])]
                    arms = None
                elif name in COST_PROGRAMS:
                    baseline = json_load(archive.read(prefix+'/campaign-0.stdout'))
                    arms = derive_arms(baseline)
                    producer_observations(baseline, arms)
                    plans = [(seed, [str(binary), '--samples', '4', '--searches', '4',
                                     '--attempt-budget', str(budget), '--seed', str(seed)])
                             for seed, budget in [(2, 64), (3, 8)]]
                else:
                    arms = None
                    plans = [(0, [str(binary), str(args.output/(name+'-state'))])]
                    if name == 'account_execution_vectors':
                        plans[0][1].extend(['--state-witness', str(args.output/'state-witness')])
                for seed, command in plans:
                    result = run_child(command, args.output/(name+'-'+str(seed)))
                    row = {'binary': name, 'binary_sha256': sha, 'seed': seed, 'process': result}
                    receipt['runs'].append(row)
                    require(result['exit_code'] == 0 and not result['timed_out'], 'CHILD_NOT_COMPLETED_SUCCESSFULLY')
                    doc = json_load((args.output/(name+'-'+str(seed))/'stdout').read_bytes())
                    if arms is not None:
                        plan = {'samples_per_case_target': 4, 'searches_per_cohort': 4,
                                'attempt_budget': 64 if seed == 2 else 8, 'seed': seed,
                                'schema': baseline['schema'], 'targets': baseline['targets']}
                        row['validation'] = producer_observations(doc, arms, plan)
                        row['required_arms'] = arms
                    else:
                        row['validation'] = {'schema': doc.get('schema'),
                                             'scope': 'native exit and JSON only; independent semantic audit separate'}
                    require(digest(binary.read_bytes()) == sha, 'BINARY_CHANGED')
                    (args.output/'replay.json').write_text(json.dumps(receipt, indent=2)+'\n')
                    print(json.dumps({'binary': name, 'seed': seed, 'exit': result['exit_code'],
                                      'cpu_ns': result['cpu_ns'], 'validation': row['validation']}), flush=True)
        receipt['completed'] = True
    except Exception as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        (args.output/'replay.json').write_text(json.dumps(receipt, indent=2)+'\n')

if __name__ == '__main__':
    main()
