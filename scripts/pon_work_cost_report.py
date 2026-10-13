#!/usr/bin/env python3
"""Collect or summarize the existing native work-cost experiment, not public acceptance.

--run builds the existing example from a clean committed tree and writes a new owned
output directory. --input summarizes recorded raw samples without calling them a fresh
measurement. --verify checks retained bytes, derivation and source/current applicability.
No peer traffic, deployment, paid provider or alternate work algorithm is involved.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from check_invariant_evidence import load, require, safe, source_bytes
from bounded_process import run_bounded

CLASSES = {'dense', 'zero', 'rank-one', 'sparse'}
COUNTERS = {'honest_attempts', 'forgery_hash_trials'}
TIMES = {'honest_winning_ns', 'valid_verify_ns', 'forgery_ns', 'invalid_verify_ns'}
SOURCE_PATHS = {'scripts/pon_work_cost_report.py',
                'formal/pon-nakamoto-v1/bounded_process.py',
                'scripts/ci/check_invariant_evidence.py',
                'config/pon/devnet-v1.json', 'config/pon/work-profile-v1.json',
                'rust-toolchain.toml'}
BUILD_COMMAND = ['cargo', 'build', '--offline', '--locked', '--release', '--manifest-path',
                 'trillionnium/Cargo.toml', '-p', 'trnm-crypto-primitives', '--example', 'pon_adversarial_cost']
FALSE_FLAGS = ('independent_accepted', 'public_network_tested',
               'honest_public_service_measured', 'work_hardness_accepted', 'production_activation')


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def target_value(text: str) -> int:
    require(isinstance(text, str) and re.fullmatch('[0-9a-f]{64}', text), 'target must be canonical 256-bit hex')
    value = int(text, 16)
    require(0 < value < 1 << 256, 'nonpositive/out-of-range target')
    return value


def summarize(raw: dict[str, Any], expected_target: str) -> dict[str, Any]:
    target = target_value(expected_target)
    require(set(raw) == {'schema', 'target', 'samples', 'fastest_adversary_implemented',
                         'hardness_accepted', 'production_activation'}, 'cost schema fields')
    require(raw['schema'] == 'pon-structured-cost-v3', 'unsupported raw cost schema')
    require(raw['target'] == expected_target, 'mixed or unexpected target')
    for flag in ('fastest_adversary_implemented', 'hardness_accepted', 'production_activation'):
        require(raw[flag] is False, 'unsupported raw qualification ' + flag)
    require(isinstance(raw['samples'], list) and raw['samples'], 'empty cost samples')
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in CLASSES}
    seen: set[tuple[str, int]] = set()
    for sample in raw['samples']:
        require(isinstance(sample, dict), 'sample must be an object')
        require(set(sample) == {'class', 'sample'} | COUNTERS | TIMES, 'cost sample fields')
        require(isinstance(sample['class'], str) and sample['class'] in CLASSES, 'unknown task class')
        require(type(sample['sample']) is int and 0 <= sample['sample'] < 1 << 64,
                'invalid sample identity')
        identity = (sample['class'], sample['sample'])
        require(identity not in seen, 'duplicate sample cannot increase evidence')
        seen.add(identity)
        for field in COUNTERS | TIMES:
            require(type(sample[field]) is int and 0 < sample[field] < 1 << 128,
                    'invalid cost counter ' + field)
        for field in COUNTERS:
            require(sample[field] <= 4096, 'native attempt bound exceeded')
        grouped[sample['class']].append(sample)
    require(all(grouped.values()), 'missing structured-input comparison')
    summaries = {}
    for name, samples in sorted(grouped.items()):
        medians = {field: statistics.median(row[field] for row in samples) for field in sorted(TIMES)}
        summaries[name] = {
            'samples': len(samples), 'median_ns': medians,
            'invalid_rejection_to_forgery_ratio': medians['invalid_verify_ns'] / medians['forgery_ns'],
            'honest_winner_to_valid_verification_ratio': medians['honest_winning_ns'] / medians['valid_verify_ns'],
            'honest_attempts_total': sum(row['honest_attempts'] for row in samples),
            'forgery_hash_trials_total': sum(row['forgery_hash_trials'] for row in samples),
        }
    p = Fraction(target + 1, 1 << 256)
    return {
        'schema': 'pon-same-target-cost-summary-v1', 'target': expected_target,
        'assumed_uniform_ticket_probability': {'numerator': str(p.numerator), 'denominator': str(p.denominator)},
        'lottery_assumptions_qualified': False, 'classes': summaries,
        'ratio_definition': 'ratio of within-class median measured durations at the same target',
        'scope': 'controlled CPU work/forgery costs; not fastest-adversary lower bound or public attack rate',
        **{flag: False for flag in FALSE_FLAGS}, 'vram_bytes': None,
    }


def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def clean() -> None:
    require(not git('status', '--porcelain'), 'measurement requires a clean committed source')


def source_inventory(paths: set[str]) -> set[str]:
    require(SOURCE_PATHS <= paths, 'missing collector/source configuration input')
    return {p for p in paths if p.startswith('trillionnium/') and not p.endswith('.md')} | SOURCE_PATHS


def current_inputs() -> dict[str, str]:
    paths = source_inventory(set(git('ls-files').splitlines()))
    return {p: digest(safe(ROOT, p).read_bytes()) for p in sorted(paths)}


def write_new(path: Path, raw: bytes) -> None:
    with path.open('xb') as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def collect(out: Path) -> dict[str, Any]:
    out = out.resolve()
    os.chdir(ROOT)  # Cargo must consume this checkout and its installed toolchain.
    clean()
    require(not out.is_relative_to(ROOT), 'measure into a new directory outside the checkout')
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    head, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    inputs = current_inputs()
    target_dir = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'trillionnium/target')).resolve()
    command = list(BUILD_COMMAND)
    build = run_bounded(command, b'', timeout=900, stdout_limit=2*1024*1024, stderr_limit=2*1024*1024)
    write_new(out / 'build.log', build.stdout + build.stderr)
    require(build.returncode == 0, 'native cost build failed; build log retained')
    binary = target_dir / 'release/examples/pon_adversarial_cost'
    binary_hash = digest(binary.read_bytes())
    started = time.monotonic_ns()
    execution = run_bounded([str(binary)], b'', timeout=120, stdout_limit=2*1024*1024, stderr_limit=65536)
    elapsed = time.monotonic_ns() - started
    write_new(out / 'native-work.json', execution.stdout)
    write_new(out / 'native-stderr.log', execution.stderr)
    require(execution.returncode == 0, 'native cost command failed; raw output retained')
    raw = load(out / 'native-work.json')
    expected_target = load(ROOT / 'config/pon/devnet-v1.json')['initial_target_hex']
    summary = summarize(raw, expected_target)
    clean()
    require(git('rev-parse', 'HEAD') == head and current_inputs() == inputs, 'source changed during measurement')
    require(digest(binary.read_bytes()) == binary_hash, 'binary changed during measurement')
    write_new(out / 'summary.json', encoded(summary))
    record = {
        'schema': 'pon-native-cost-execution-v1', 'source_commit': head, 'source_tree': tree,
        'source_clean_before_and_after': True, 'source_files_sha256': inputs,
        'binary_sha256': binary_hash, 'build_command': command, 'build_returncode': build.returncode,
        'command': [str(binary)], 'returncode': execution.returncode, 'process_wall_ns': elapsed,
        'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'platform': platform.platform(), 'python': platform.python_version(),
        'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
        'target': expected_target, 'test_threads': os.environ.get('RUST_TEST_THREADS'),
        **{flag: False for flag in FALSE_FLAGS},
    }
    write_new(out / 'execution.json', encoded(record))
    manifest = {'schema': 'pon-native-cost-files-v1', 'files': {
        name: digest((out / name).read_bytes()) for name in
        ('build.log', 'native-work.json', 'native-stderr.log', 'summary.json', 'execution.json')},
        **{flag: False for flag in FALSE_FLAGS}}
    write_new(out / 'manifest.json', encoded(manifest))
    return {'out': str(out), 'measured_commit': head, 'binary_sha256': binary_hash, 'summary': summary}


def verify(out: Path, require_current: bool = True) -> dict[str, Any]:
    out = out.resolve()
    manifest = load(safe(out, 'manifest.json'))
    require(manifest['schema'] == 'pon-native-cost-files-v1', 'manifest schema')
    required = {'build.log', 'native-work.json', 'native-stderr.log', 'summary.json', 'execution.json'}
    require(set(manifest['files']) == required, 'missing or extra collection artifact')
    for name, expected in manifest['files'].items():
        require(digest(safe(out, name).read_bytes()) == expected, 'changed retained artifact ' + name)
    record = load(out / 'execution.json')
    require(record['schema'] == 'pon-native-cost-execution-v1' and
            record['source_clean_before_and_after'] is True, 'execution scope')
    for value in (manifest, record):
        for flag in FALSE_FLAGS:
            require(value[flag] is False, 'false collection authority ' + flag)
    require(type(record['returncode']) is int and record['returncode'] == 0 and
            type(record['build_returncode']) is int and record['build_returncode'] == 0, 'failed recorded command')
    require(re.fullmatch('[0-9a-f]{64}', record['binary_sha256']), 'missing binary identity')
    commit = record['source_commit']
    require(re.fullmatch('[0-9a-f]{40}', commit), 'bad source identity')
    require(git('rev-parse', commit + '^{tree}') == record['source_tree'], 'wrong source tree')
    require(record['build_command'] == BUILD_COMMAND, 'unexpected native build command')
    require(isinstance(record['command'], list) and len(record['command']) == 1 and
            Path(record['command'][0]).name == 'pon_adversarial_cost', 'unexpected native cost command')
    require(type(record['process_wall_ns']) is int and record['process_wall_ns'] > 0, 'invalid process timing')
    measured_inventory = source_inventory(set(git('ls-tree', '-r', '--name-only', commit).splitlines()))
    require(set(record['source_files_sha256']) == measured_inventory, 'incomplete measured source inventory')
    original = source_bytes(ROOT, commit, list(record['source_files_sha256']))
    for name, raw in original.items():
        require(digest(raw) == record['source_files_sha256'][name], 'wrong measured source ' + name)
    source_target = json.loads(original['config/pon/devnet-v1.json'])['initial_target_hex']
    require(record['target'] == source_target, 'target differs from measured configuration')
    expected_summary = summarize(load(out / 'native-work.json'), source_target)
    require(encoded(expected_summary) == safe(out, 'summary.json').read_bytes(), 'summary differs from raw observations')
    matches = record['source_files_sha256'] == current_inputs()
    if require_current:
        require(matches, 'source changed: retain historical costs and execute a new collection')
    return {'source_commit': commit, 'current_measured_inputs_match': matches,
            'retained_observations_verified': True, 'experiment_reexecuted_by_verifier': False,
            **{flag: False for flag in FALSE_FLAGS}}



# This policy is reporting-only: it is not a genesis parameter or activation switch.
ACCEPTANCE_PROFILE = ROOT / 'config/pon/work-security-acceptance-v1.json'
PREPARED_FIELDS = {'class', 'target', 'sample', 'baseline_first', 'attempts', 'baseline_ns',
                   'prepared_setup_ns', 'prepared_search_ns', 'prepared_total_ns',
                   'original_verifier_ns', 'proof_bytes', 'proof_commitment'}


def positive(value: Any, name: str) -> int:
    require(type(value) is int and 0 < value < 1 << 128, 'invalid positive integer ' + name)
    return value


def prepared_samples(raw: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    require(set(raw) == {'schema', 'samples', 'fastest_adversary_qualified',
                         'public_service_measured', 'production_activation'}, 'prepared schema fields')
    require(raw['schema'] == 'pon-prepared-producer-cost-v1', 'prepared schema')
    for flag in ('fastest_adversary_qualified', 'public_service_measured', 'production_activation'):
        require(raw[flag] is False, 'unsupported prepared claim ' + flag)
    targets = {'7' + 'f' * 63, '07' + 'f' * 62}
    expected = {(c, t, n) for c in CLASSES for t in targets for n in range(8)}
    seen = set()
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    require(isinstance(raw['samples'], list), 'prepared samples list')
    for row in raw['samples']:
        require(isinstance(row, dict) and set(row) == PREPARED_FIELDS, 'prepared sample fields')
        require(isinstance(row['class'], str) and isinstance(row['target'], str)
                and type(row['sample']) is int, 'prepared sample identity types')
        key = row['class'], row['target'], row['sample']
        require(key in expected and key not in seen, 'missing/duplicate/unexpected prepared identity')
        seen.add(key)
        for field in PREPARED_FIELDS - {'class', 'target', 'sample', 'baseline_first', 'proof_commitment'}:
            positive(row[field], field)
        require(row['attempts'] <= 4096 and row['proof_bytes'] == 49188, 'prepared bounds')
        require(row['prepared_total_ns'] == row['prepared_setup_ns'] + row['prepared_search_ns'],
                'prepared setup must remain charged')
        require(row['baseline_first'] is (row['sample'] % 2 == 0), 'paired measurement ordering')
        require(isinstance(row['proof_commitment'], str) and
                re.fullmatch('[0-9a-f]{64}', row['proof_commitment']), 'proof commitment')
        groups.setdefault(key[:2], []).append(row)
    require(seen == expected, 'incomplete prepared comparison')
    return groups


def service_acceptance(raw: dict[str, Any] | None, target: str, policy: dict[str, Any]) -> dict[str, Any]:
    if raw is None:
        return {'status': 'unmeasured', 'reason': 'no complete honest/attacker event ledger supplied'}
    require(set(raw) == {'schema', 'target', 'window_ns', 'honest', 'attacker', 'scope',
                         'independent_accepted', 'production_activation', 'acceptance_profile_sha256',
                         'attacker_setup_cpu_ns'}, 'service fields')
    require(raw['schema'] == 'pon-work-service-events-v1' and raw['target'] == target,
            'service schema/target')
    require(raw['scope'] == 'controlled-local' and raw['independent_accepted'] is False
            and raw['production_activation'] is False, 'service scope')
    require(raw['acceptance_profile_sha256'] == digest(ACCEPTANCE_PROFILE.read_bytes()),
            'service measured under a different acceptance policy')
    setup = positive(raw['attacker_setup_cpu_ns'], 'attacker_setup_cpu_ns')
    window = positive(raw['window_ns'], 'window_ns')
    require(isinstance(raw['honest'], list) and isinstance(raw['attacker'], list), 'event arrays')
    latencies = []
    failures = 0
    for kind in ('honest', 'attacker'):
        seen = set()
        for row in raw[kind]:
            fields = {'id', 'offered_ns', 'finished_ns', 'outcome'}
            if kind == 'attacker':
                fields |= {'construction_cpu_ns', 'encoded_bytes', 'rejection_cpu_ns'}
            require(isinstance(row, dict) and set(row) == fields, 'event fields')
            require(type(row['id']) is int and row['id'] >= 0 and row['id'] not in seen, 'event identity')
            seen.add(row['id'])
            require(type(row['offered_ns']) is int and 0 <= row['offered_ns'] < window, 'offered time')
            require(row['outcome'] in ('accepted', 'rejected', 'timeout', 'dropped'), 'event outcome')
            end = row['finished_ns']
            require(end is None or (type(end) is int and row['offered_ns'] <= end <= window), 'finished time')
            require(end is not None or row['outcome'] in ('timeout', 'dropped'), 'missing completion')
            if kind == 'honest':
                failures += row['outcome'] != 'accepted'
                # Timeouts and drops stay in the offered denominator and tail distribution.
                latencies.append((end if end is not None else window) - row['offered_ns'])
            else:
                require(row['outcome'] != 'accepted', 'forged work accepted')
                for field in ('construction_cpu_ns', 'encoded_bytes', 'rejection_cpu_ns'):
                    positive(row[field], field)
    latency = sorted(latencies)
    p99 = latency[(99 * len(latency) + 99) // 100 - 1] if latency else None
    cpu = setup + sum(r['construction_cpu_ns'] for r in raw['attacker'])
    spans = {kind: (max(r['offered_ns'] for r in raw[kind]) - min(r['offered_ns'] for r in raw[kind]))
             if raw[kind] else 0 for kind in ('honest', 'attacker')}
    wire = sum(r['encoded_bytes'] for r in raw['attacker'])
    # Separate population spans cannot establish concurrent offered load: two
    # disjoint 49-second campaigns can satisfy each span inside a long window.
    # These are source-bound LOCAL screening checks, not attack saturation proof.
    offers = {kind: sorted(row['offered_ns'] for row in raw[kind])
              for kind in ('honest', 'attacker')}
    shared_offer_span = (max(0, min(offers['honest'][-1], offers['attacker'][-1])
                             - max(offers['honest'][0], offers['attacker'][0]))
                         if offers['honest'] and offers['attacker'] else 0)
    bucket_width = max(1, policy['minimum_window_ns'] // 10)
    shared_buckets = ({time // bucket_width for time in offers['honest']}
                      & {time // bucket_width for time in offers['attacker']})
    minimum_shared_buckets = max(1, policy['minimum_offer_span_ns'] // bucket_width - 1)
    checks = {
        'minimum_window': window >= policy['minimum_window_ns'],
        'honest_offer_span': spans['honest'] >= policy['minimum_offer_span_ns'],
        'attacker_offer_span': spans['attacker'] >= policy['minimum_offer_span_ns'],
        'shared_offer_interval': shared_offer_span >= policy['minimum_offer_span_ns'] // 2,
        'shared_offer_buckets': len(shared_buckets) >= minimum_shared_buckets,
        'honest_offered_denominator': len(latency) >= policy['minimum_honest_offered'],
        'honest_failure_limit': failures <= policy['maximum_honest_failures'],
        'honest_p99_deadline': p99 is not None and p99 <= policy['honest_p99_deadline_ns'],
        'attacker_offered_denominator': len(raw['attacker']) >= policy['minimum_attacker_offered'],
        'attacker_cpu_budget': cpu <= policy['attacker_cpu_budget_ns'],
        'attacker_byte_budget': wire <= policy['attacker_byte_budget'],
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'honest_offered': len(latency),
            'honest_completed': sum(r['finished_ns'] is not None for r in raw['honest']),
            'honest_accepted': len(latency) - failures,
            'honest_failures': failures, 'honest_p99_ns': p99,
            'attacker_offered': len(raw['attacker']), 'attacker_construction_cpu_ns': cpu,
            'attacker_setup_cpu_ns': setup, 'offer_span_ns': spans,
            'shared_offer_span_ns': shared_offer_span, 'shared_offer_buckets': len(shared_buckets),
            'shared_bucket_width_ns': bucket_width, 'minimum_shared_buckets': minimum_shared_buckets,
            'attacker_encoded_bytes': wire,
            'defender_rejection_cpu_ns': sum(r['rejection_cpu_ns'] for r in raw['attacker']),
            'window_ns': window, 'scope': 'input-contract consistency only; supplied local ledger is not independently authenticated',
            'hostile_service_qualified': False}


def acceptance(raw: dict[str, Any], prepared: dict[str, Any], expected_target: str,
               service: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = load(ACCEPTANCE_PROFILE)
    require(policy['production_activation'] is False and policy['consensus_parameter'] is False,
            'report policy cannot activate consensus')
    baseline = summarize(raw, expected_target)
    groups = prepared_samples(prepared)
    rows = []
    for name in sorted(CLASSES):
        paired = groups[name, expected_target]
        invalid = [r for r in raw['samples'] if r['class'] == name]
        require(len(invalid) >= policy['minimum_cost_samples_per_class'], 'insufficient invalid sample count')
        for horizon in policy['setup_amortization_winners']:
            # Select an implementation over ALL rows, never the fastest individual sample.
            original = Fraction(sum(r['baseline_ns'] for r in paired), len(paired))
            optimized = Fraction(sum(r['prepared_search_ns'] for r in paired), len(paired)) + \
                Fraction(sum(r['prepared_setup_ns'] for r in paired), len(paired) * horizon)
            cheapest = min(original, optimized)
            verification = Fraction(sum(r['original_verifier_ns'] for r in paired), len(paired))
            rejection = Fraction(sum(r['invalid_verify_ns'] for r in invalid), len(invalid))
            forgery = Fraction(sum(r['forgery_ns'] for r in invalid), len(invalid))
            # Existing forgery samples start from an already obtained proof prefix.
            # Charge that measured initial proof cost once, then amortize explicitly.
            prefix = Fraction(sum(r['honest_winning_ns'] for r in invalid), len(invalid))
            charged_forgery = forgery + prefix / horizon
            rows.append({'class': name, 'target': expected_target, 'amortization_winners': horizon,
                         'sample_count': len(paired), 'honest_attempts': sum(r['attempts'] for r in paired),
                         'forgery_hash_trials': sum(r['forgery_hash_trials'] for r in invalid),
                         'baseline_mean_winner_ns': float(original), 'prepared_mean_winner_ns': float(optimized),
                         'cheapest_supplied_valid_producer': 'prepared' if optimized < original else 'baseline',
                         'cheapest_mean_winner_ns': float(cheapest),
                         'valid_verifier_mean_ns': float(verification),
                         'winner_to_verifier_ratio': float(cheapest / verification),
                         'invalid_rejection_mean_ns': float(rejection), 'forgery_marginal_mean_ns': float(forgery),
                         'forgery_charged_mean_ns': float(charged_forgery),
                         'marginal_rejection_amplification': float(rejection / forgery),
                         'charged_rejection_amplification': float(rejection / charged_forgery),
                         'winning_cost_gate': cheapest >= verification * policy['minimum_winner_to_verifier_ratio'],
                         'invalid_cost_gate': rejection <= forgery * policy['maximum_marginal_rejection_amplification']})
    service_result = service_acceptance(service, expected_target, policy['service'])
    local_pass = all(r['winning_cost_gate'] and r['invalid_cost_gate'] for r in rows) and service_result['status'] == 'pass'
    return {'schema': 'pon-work-security-acceptance-report-v1',
            'profile_sha256': digest(ACCEPTANCE_PROFILE.read_bytes()), 'target': expected_target,
            'input_sha256': {'invalid_cost': digest(encoded(raw)), 'prepared_cost': digest(encoded(prepared)),
                             'service': digest(encoded(service)) if service is not None else None},
            'local_observation_gate': 'pass' if local_pass else 'not-accepted',
            'fresh_measurement': False, 'source_applicability_verified': False,
            'gate_scope': 'proposed local diagnostic thresholds; not preregistered/deployment acceptance',
            'costs': rows, 'service': service_result,
            'oracle_scope': 'original Rust verifier plus separately coded Python oracle; same development authorship',
            'external_review_status': 'unmeasured',
            'limitations': ['supplied observations require separate source/binary receipt verification',
                           'amortization beyond one winner is modeled, not measured multi-winner reuse',
                           'invalid and prepared samples share target/task class, not nonce streams',
                           'prefix preparation is a conservative measured honest proof cost, not cheapest attack setup',
                           'fastest supplied mean is not a lower bound on adversarial algorithms or hardware',
                           'bounded successful samples do not measure exhausted searches or a public arrival process',
                           'joint offer spans/buckets are local timing checks, not authenticated arrival or attack saturation',
                           'service budget maxima do not establish adversarial saturation or sufficient attack intensity'],
            'baseline_summary': baseline, **{flag: False for flag in FALSE_FLAGS}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--run', action='store_true')
    mode.add_argument('--input', type=Path)
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--expected-target')
    parser.add_argument('--historical', action='store_true')
    parser.add_argument('--prepared', type=Path, help='evaluate supplied paired costs under the reporting-only acceptance profile')
    parser.add_argument('--service', type=Path, help='complete local honest/attacker event ledger; missing is unmeasured')
    parser.add_argument('--require-local-acceptance', action='store_true', help='exit 2 unless every local observation gate passes; never grants external acceptance')
    args = parser.parse_args()
    require(not (args.prepared or args.service or args.require_local_acceptance) or
            (args.input is not None and args.prepared is not None),
            'acceptance options require --input and --prepared')
    if args.run:
        require(args.out is not None, '--run requires --out')
        value = collect(args.out)
    elif args.verify:
        value = verify(args.verify, require_current=not args.historical)
    else:
        require(args.expected_target is not None, '--input requires an explicit --expected-target')
        if args.prepared:
            value = acceptance(load(args.input), load(args.prepared), args.expected_target,
                               load(args.service) if args.service else None)
        else:
            require(args.service is None, '--service requires --prepared')
            value = {'input_sha256': digest(args.input.read_bytes()), 'fresh_measurement': False,
                     'summary': summarize(load(args.input), args.expected_target)}
    print(encoded(value).decode(), end='')
    if args.require_local_acceptance and value['local_observation_gate'] != 'pass':
        sys.exit(2)
