"""Independently check archived observations and recompute paired cost accounting.

This reads original GitHub artifacts. It does not rerun a native producer or
claim physical hardware attestation, an energy result, or a global minimum.
"""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = '974932be6dcfe830ce1ce92d58cb10e89cb8358d'
TREE = 'd4435ebdecac15e9a3fb2852eb1f835b336e452e'
SPECS = [
    ('x64', 'x86_64', 12885187154, '0d0f5e9db5c15f0b7218367be014716da07165fd06bdc995932553f35a10cde8'),
    ('arm64', 'aarch64', 12884734562, '8647fc9462b84a1e2f95a204b3443cf0aa0794f04603fdc73f3025dac5f8e454'),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_pairs(items):
    result = {}
    for key, value in items:
        assert key not in result, ('duplicate JSON key', key)
        result[key] = value
    return result


def parse(data):
    def invalid_constant(value):
        raise ValueError(value)
    return json.loads(data, object_pairs_hook=unique_pairs,
                      parse_constant=invalid_constant)


def identity(cohort, trial):
    return (cohort['task'], cohort['proof_prefix_sha256'], trial['challenge'],
            trial['trace'], trial['canonical_proof_sha256'])


def audit(label, machine, artifact_id, expected_sha):
    path = ROOT / f'ticket-first-{label}-974932be.zip'
    archive_bytes = path.read_bytes()
    assert sha(archive_bytes) == expected_sha
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)) == 25
        files = {name: archive.read(name) for name in names}
    capture = parse(files['cost/capture.json'])
    summary = parse(files['cost/summary.json'])
    source = parse(files['source-before.json'])
    assert source == parse(files['source-after.json'])
    assert source['tested_commit'] == HEAD and source['tested_tree'] == TREE
    assert source['tracked_worktree_verified'] is True
    assert capture['source']['commit'] == HEAD and capture['source']['tree'] == TREE
    assert capture['exit_code'] == 0 and capture['timed_out'] is False
    assert capture['machine'] == machine
    binary_hash = sha(files[f'pon_ticket_first_cost_v1.{machine}'])
    assert binary_hash == capture['binary_sha256_before'] == capture['binary_sha256_after']
    assert sha(files['cost/stdout.jsonl.gz']) == capture['stdout_gzip_sha256']
    assert sha(files['cost/stderr.log']) == capture['stderr_sha256']
    raw_bytes = gzip.decompress(files['cost/stdout.jsonl.gz'])
    assert sha(raw_bytes) == capture['stdout_uncompressed_sha256']
    assert len(raw_bytes) == capture['stdout_bytes']
    rows = [parse(line) for line in raw_bytes.splitlines()]
    assert rows[0]['kind'] == 'begin' and rows[-1]['status'] == 'complete'
    assert rows[0]['winning_only_still_computes_all_transcript_tiles'] is True
    cohorts = rows[1:-1]
    assert len(cohorts) == summary['cohorts'] == 96
    assert len({(c['round'], c['search_horizon'], c['reuse'], c['arm']) for c in cohorts}) == 96
    observations = collections.Counter()
    categories = {}
    native_packets = set()
    stable_streams = {}
    attempted = admitted = materialized = 0
    for c in cohorts:
        assert c['kind'] == 'cohort' and c['status'] == 'complete'
        assert c['fresh_store'] is True and c['explicit_activation_calls'] == 0
        trials = [t for search in c['searches'] for t in search['trials']]
        wins = [t for t in trials if t['target_hit']]
        assert len(trials) == c['attempts']
        assert len(wins) == c['winners'] == c['first_native_admissions'] == c['cold_packet_readbacks']
        assert c['winners'] + c['exhausted'] == c['search_horizon'] == len(c['searches'])
        assert len(c['retained_packets']) == len(wins)
        assert [p['id'] for p in c['retained_packets']] == [t['packet_id'] for t in wins]
        for search in c['searches']:
            ts = search['trials']
            assert 1 <= len(ts) <= c['attempt_budget']
            assert search['won'] == ts[-1]['target_hit']
            assert not any(t['target_hit'] for t in ts[:-1])
            if not search['won']:
                assert len(ts) == c['attempt_budget']
            for t in ts:
                assert t['target_hit'] == (bytes.fromhex(t['ticket']) <= bytes.fromhex(c['target']))
                expected_materialized = t['target_hit'] or not c['arm'].endswith('-ticket-first')
                assert t['proof_materialized'] == expected_materialized
                key = identity(c, t)
                category = ('winning_trials' if t['target_hit'] else
                            'misses_before_winner' if search['won'] else
                            'exhausted_search_trials')
                assert categories.setdefault(key, category) == category
                observations[key] += 1
                if t['target_hit']:
                    assert t['packet_bytes'] == 49508
                    native_packets.add(t['packet_id'])
        mats = sum(t['proof_materialized'] for t in trials)
        assert mats == c['proof_materializations']
        assert c['proof_bytes_materialized'] == 49188 * mats
        for clock in ['wall_ns', 'process_cpu_ns']:
            assert sum(t['generation'][clock] for t in trials) == c['phases']['all_attempt_generation'][clock]
            assert sum(p[clock] for p in c['phases'].values()) == c['all_exclusive_phases'][clock]
            assert sum(c['phases'][p][clock] for p in ['producer_setup', 'all_attempt_generation', 'packet_encoding', 'first_native_admission']) == c['recurring_producer_encode_admission'][clock]
            assert c['observed_outer'][clock] >= c['all_exclusive_phases'][clock]
        stream = [(t['nonce'], t['challenge'], t['trace'], t['ticket'], t['canonical_proof_sha256'], t['target_hit'], t.get('packet_id')) for t in trials]
        pair_key = (c['round'], c['search_horizon'])
        assert stable_streams.setdefault(pair_key, stream) == stream
        attempted += len(trials)
        admitted += len(wins)
        materialized += mats
    assert attempted == summary['attempts_including_paired_repetitions'] == 16404
    assert admitted == summary['first_admission_calls'] == 7860
    assert len(native_packets) == summary['distinct_fixture_packet_ids_across_paired_cohorts'] == 655
    assert len(observations) == 1367 and set(observations.values()) == {12}
    assert dict(collections.Counter(categories.values())) == {'winning_trials': 655, 'misses_before_winner': 688, 'exhausted_search_trials': 24}
    replay_receipt = parse(files['independent-w1-replay/receipt.json'])
    assert replay_receipt['complete'] is True
    assert replay_receipt['all_observed_w1_statements_replayed'] is True
    replay_rows = [parse(line) for line in files['independent-w1-replay/replay.jsonl'].splitlines()]
    replay_results = [r for r in replay_rows if r['kind'] == 'input-result']
    replay_keys = set()
    for r in replay_results:
        assert r['product_matches'] is True and r['trace_matches'] is True
        assert r['actual_trace'] == r['expected_trace']
        key = (r['task'], r['prefix_sha256'], r['challenge'], r['actual_trace'], r['canonical_proof_sha256'])
        assert key not in replay_keys and categories[key] == r['category']
        replay_keys.add(key)
    assert replay_keys == set(observations)
    assert replay_rows[-1]['kind'] == 'terminal' and replay_rows[-1]['complete'] is True
    comparisons = []
    for producer in ['generic', 'limb']:
        reference = [c for c in cohorts if c['search_horizon'] == 256 and c['reuse'] and c['arm'] == producer + '-candidate-all']
        alternative = [c for c in cohorts if c['search_horizon'] == 256 and c['reuse'] and c['arm'] == producer + '-ticket-first']
        assert len(reference) == len(alternative) == 2
        winners = sum(c['winners'] for c in reference)
        assert winners == sum(c['winners'] for c in alternative)
        result = {'producer': producer, 'horizon': 256, 'reuse': True, 'paired_rounds': 2,
                  'first_admissions_per_arm': winners,
                  'attempts_per_arm': sum(c['attempts'] for c in reference),
                  'reference_materializations': sum(c['proof_materializations'] for c in reference),
                  'ticket_first_materializations': sum(c['proof_materializations'] for c in alternative)}
        for display, field in [('recurring', 'recurring_producer_encode_admission'), ('outer', 'observed_outer')]:
            ref = sum(c[field]['process_cpu_ns'] for c in reference)
            alt = sum(c[field]['process_cpu_ns'] for c in alternative)
            differences = [a[field]['process_cpu_ns'] - r[field]['process_cpu_ns'] for r, a in zip(reference, alternative)]
            result[display + '_cpu_ms_per_admission'] = {'reference': ref / winners / 1e6, 'ticket_first': alt / winners / 1e6, 'reference_over_ticket_first': ref / alt, 'paired_round_alternative_minus_reference_ns': differences}
        comparisons.append(result)
    result = {
        'architecture': machine, 'artifact_id': artifact_id, 'archive_sha256': expected_sha,
        'binary_sha256': binary_hash, 'cohorts': len(cohorts),
        'attempts_including_paired_repetitions': attempted,
        'repeated_first_admissions': admitted, 'distinct_packets': len(native_packets),
        'unique_w1_inputs_bound_to_original_replay': len(replay_keys),
        'distinct_input_partition': dict(collections.Counter(categories.values())),
        'source_before_after_equal': True, 'raw_recomputed_cost_accounting_passed': True,
        'complete_capture_cpu_seconds': capture['child_user_cpu_seconds'] + capture['child_system_cpu_seconds'],
        'complete_capture_wall_seconds': capture['elapsed_ns'] / 1e9,
        'capture_max_single_child_rss_kib': capture['child_max_rss_kib'],
        'host_claims': parse(files['host.json']), 'comparisons': comparisons,
        'archive_inventory': [{'path': p, 'bytes': len(b), 'sha256': sha(b)} for p, b in sorted(files.items())],
    }
    return result, stable_streams


def main():
    outputs = [audit(*spec) for spec in SPECS]
    assert outputs[0][1] == outputs[1][1]
    report = {
        'schema': 'independent-ticket-first-archive-audit-v1',
        'source_commit': HEAD, 'source_tree': TREE,
        'original_run': 'https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40845715638',
        'all_checks_passed': True, 'both_architectures_have_identical_fixed_searches': True,
        'results': [item[0] for item in outputs],
        'scope': [
            'The archive bytes, source records, ELF hashes, raw cost accounting, paired observations and all original independent W1 replay results were checked here.',
            'This audit did not execute the native ELF or recompute W1 arithmetic again; original replay evidence is bound to every unique observed input.',
            'Repeated admissions count repeated fresh-node experiments; 655 distinct packet IDs are not 7860 independent work successes.',
            'Each reported comparison uses the same fixed implementation across both rounds; no per-round fastest strategy is constructed.',
            'Recurring and outer clocks are nested. Complete process capture also includes final serialization and cleanup outside cohort outer clocks.',
            'Shared hosted CPU observations do not establish a global cheapest solver, hardware identity, GPU or ASIC performance, energy, active-chain rewards, public fairness or transparent-proof production costs.',
        ],
    }
    target = ROOT / 'ticket-first-974932be-independent-audit.json'
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'report': str(target), 'pass': True, 'comparisons': [{'architecture': r['architecture'], 'comparisons': r['comparisons']} for r in report['results']]}))


if __name__ == '__main__':
    main()
