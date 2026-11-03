#!/usr/bin/env python3
"""Independent archived-observation audit of legal-ticket V5 at 974932be.

No native ELF is executed. V5/V3 have observation hashes, not archived packet
payloads. V4 payload SHA256/length checks are independent here; W1 arithmetic
and native admission are not replayed. No ticket-first/1367-input receipt is
used as evidence for this experiment.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = '974932be6dcfe830ce1ce92d58cb10e89cb8358d'
TREE = 'd4435ebdecac15e9a3fb2852eb1f835b336e452e'
REPO = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain'
SPECS = (
    ('x64', 'x86_64', 62, 12884798290,
     'a614e74eb1795aaffe9435667316f0a1f515e89cada6d6c6753dd438307d76e7'),
    ('arm64', 'aarch64', 183, 12885052371,
     '23673732fdfcfdb7ab6eef4ad4dff475c5349c129f3bc851b75b3068f00dc8ec'),
)
ALL_ARMS = (
    'scalar-original', 'prepared-generic', 'prepared-structured',
    'tiled-classical', 'tiled-strassen-one-level', 'paired-product',
    'blocked-zero', 'blocked-zero-integer-paired', 'blocked-one-zero-rank-one',
    'maintenance-periodic', 'maintenance-integer-paired',
    'maintenance-prefix', 'maintenance-limb',
)
LEGAL = (0, 1, 3, 4, 5, 9, 10, 11, 12)
ARMS = tuple(ALL_ARMS[i] for i in LEGAL)
HORIZONS = (1, 8, 64, 256)
PHASES = (
    'directory', 'node_open', 'bootstrap_material', 'template_acquisition',
    'matrix_material', 'producer_setup', 'all_attempt_generation',
    'packet_encoding', 'first_native_admission', 'node_close',
    'cold_node_open', 'cold_packet_readback', 'cold_node_close',
)
RECURRING = ('producer_setup', 'all_attempt_generation',
             'packet_encoding', 'first_native_admission')
CLOCKS = ('process_cpu_ns', 'wall_ns')
VERSIONS = {
    'cost': ('pon_legal_ticket_cost_v5',
             'pon-legal-ticket-first-admission-cost-v5', 144, 600),
    'original-v3': ('pon_legal_ticket_cost_v3',
                    'pon-legal-ticket-first-admission-cost-v3', 8, 240),
    'original-batch-v4': ('pon_legal_ticket_batch_v4',
                          'pon-legal-ticket-cpu-batch-cost-v4', 12, 240),
}


def require(ok, context):
    if not ok:
        raise ValueError(context)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, ('duplicate JSON field', key))
            out[key] = value
        return out
    def bad(value):
        raise ValueError(('nonfinite JSON number', value))
    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad)


def uint(value):
    require(type(value) is int and value >= 0, ('unsigned observation', value))
    return value


def hexstr(value, size=64):
    require(isinstance(value, str) and len(value) == size
            and all(c in '0123456789abcdef' for c in value), 'hex observation')
    return value


def timing(value):
    require(set(value) == set(CLOCKS), ('clock inventory', value))
    for item in value.values():
        uint(item)
    return value


def sumtiming(values):
    values = [timing(v) for v in values]
    return {clock: sum(v[clock] for v in values) for clock in CLOCKS}


def observation_stream(cohort):
    """Only observed identities; does not reconstruct full-proof stream SHA."""
    return (
        cohort['parent'], cohort['task'], cohort['target'],
        cohort['native_template_header'],
        tuple((s['search'], t['trial'], t['nonce'], t['challenge'],
               t['proof_sha256'], t['ticket'], t['target_hit'],
               t.get('packet_id'), t.get('packet_bytes'))
              for s in cohort['searches'] for t in s['trials']),
        tuple((p['id'], p['bytes'], p['sha256'])
              for p in cohort['retained_packets']),
    )


def validate_cohorts(rows, folder, archive, summary):
    is_v5 = folder == 'cost'
    is_batch = folder == 'original-batch-v4'
    begin, terminal = rows[0], rows[-1]
    _, schema, count, budget = VERSIONS[folder]
    require(len(rows) == count + 2, ('raw row count', folder))
    require(all(r['schema'] == schema for r in rows), 'schema')
    require(begin['kind'] == 'begin' and terminal['kind'] == 'terminal'
            and terminal['status'] == 'complete' and terminal['cohorts'] == count,
            'complete begin/cohorts/terminal')
    require(terminal['wall_ns'] <= budget * 10**9, 'original native budget')
    require((begin['rounds'], begin['attempts'], begin['seed'],
             begin['budget_seconds'], begin['native_workers']) == (2, 8, 1, budget, 1),
            'frozen native run settings')
    require(begin['positive_legal_tickets_only'] is True and
            begin['standalone_verifier_added_to_native_admission'] is False, 'begin scope')
    for key in ('gpu_measured', 'energy_measured', 'exclusive_host',
                'hardware_authenticated', 'hardware_batching_measured',
                'global_minimum_proved'):
        require(begin[key] is False, ('unsupported qualification', key))
    for key in ('active_chain_rewards_measured', 'production_qualified', 'global_minimum_proved'):
        require(terminal[key] is False, ('terminal qualification', key))
    timing(begin['settings_setup'])
    expected_order = []
    if is_v5:
        require(begin['arms'] == list(ALL_ARMS) and begin['legal_arm_indices'] == list(LEGAL)
                and begin['horizons'] == list(HORIZONS), 'constructor/legal/horizon roster')
        require(len(begin['support_probe']) == 13, 'all thirteen real constructor probes')
        for i, probe in enumerate(begin['support_probe']):
            require(probe['strategy'] == ALL_ARMS[i] and probe['strategy_index'] == i
                    and probe['supported'] is (i in LEGAL), 'legal constructor support')
            timing(probe['preparation'])
        timing(begin['support_matrix_material'])
        for r in range(2):
            for hi, h in enumerate(HORIZONS):
                for reuse in (False, True):
                    arms = list(ARMS if r == 0 else ARMS[::-1])
                    shift = (hi + int(reuse)) % 9
                    arms = arms[shift:] + arms[:shift]
                    expected_order.extend((r, h, reuse, arm) for arm in arms)
    else:
        require(begin['searches'] == 64, 'legacy search horizon')
        for r in range(2):
            arms = ['prepared-general', 'maintenance-split-limb']
            if r:
                arms.reverse()
            if is_batch:
                require(begin['cpu_batch_workers'] == [1, 2, 4]
                        and begin['cpu_batching_measured'] is True
                        and begin['winning_packet_payloads_retained'] is True, 'real CPU batch settings')
                for workers in ([1, 2, 4] if r == 0 else [4, 2, 1]):
                    expected_order.extend((r, workers, True, arm) for arm in arms)
            else:
                for reuse in (False, True):
                    expected_order.extend((r, 64, reuse, arm) for arm in arms)
    cohorts = rows[1:-1]
    paired, reported_streams, all_ids = {}, {}, set()
    identities, categories = collections.Counter(), {}
    totals = collections.Counter()
    packets_checked = set()
    receipts = []
    for position, c in enumerate(cohorts):
        require(c['kind'] == 'cohort' and c['status'] == 'complete', 'cohort completion')
        h, r, reuse = uint(c['search_horizon']), uint(c['round']), c['reuse']
        require(type(reuse) is bool, 'reuse boolean')
        key = (r, c['batch_workers'] if is_batch else h, reuse, c['strategy'])
        require(key == expected_order[position], ('full fixed ordered grid', position, key))
        require(c['order'] == position % (9 if is_v5 else 2), 'balanced declared order')
        if is_v5:
            require(c['strategy_index'] == ALL_ARMS.index(c['strategy']), 'strategy index')
        require(c['fresh_store'] is True and c['template_seed_admitted'] is False
                and c['explicit_activation_calls'] == 0
                and c['standalone_verifier_added_to_native_admission'] is False,
                'fresh first-admission scope; no standalone double count')
        require(c['attempt_budget'] == 8 and c['producer_setup_calls'] == (1 if reuse else h),
                'actual preparation reuse plan')
        for field in ('parent', 'target', 'task', 'stream_sha256'):
            hexstr(c[field])
        hexstr(c['native_template_header'], 636)
        require(set(c['phases']) == set(PHASES) | ({'packet_archival'} if is_batch else set()),
                'complete exclusive phase inventory')
        require(sumtiming(c['phases'].values()) == timing(c['all_exclusive_phases']),
                'independent exclusive clock accounting')
        require(sumtiming(c['phases'][p] for p in RECURRING)
                == timing(c['recurring_producer_encode_admission']), 'recurring clock accounting')
        outer = timing(c['observed_outer'])
        for clock in CLOCKS:
            require(outer[clock] >= c['all_exclusive_phases'][clock], 'nested outer clock')
        require(len(c['searches']) == h, 'all searches retained')
        trials, winning = [], []
        for i, search in enumerate(c['searches']):
            require(search['search'] == i and type(search['won']) is bool, 'search order/result')
            ts = search['trials']
            require(1 <= len(ts) <= 8 and (search['won'] or len(ts) == 8), 'attempts/exhaustion')
            if is_batch:
                require(search['worker'] == i % c['batch_workers'], 'real batch ownership')
                hexstr(search['search_stream_sha256'])
            for j, t in enumerate(ts):
                require(t['trial'] == j and t['nonce'] == (1 << 32) + r * (1 << 24)
                        + (h * 4096 if is_v5 else 0) + i * 8 + j, 'fixed disjoint nonce window')
                for field in ('challenge', 'proof_sha256', 'ticket'):
                    hexstr(t[field])
                hit = bytes.fromhex(t['ticket']) <= bytes.fromhex(c['target'])
                require(type(t['target_hit']) is bool and t['target_hit'] == hit
                        and hit == (search['won'] and j == len(ts) - 1),
                        'original <= predicate; first hit only')
                ident = (c['task'], c['native_template_header'], t['nonce'],
                         t['challenge'], t['proof_sha256'], t['ticket'])
                category = ('winning_trials' if hit else 'misses_before_winner'
                            if search['won'] else 'exhausted_search_trials')
                require(categories.setdefault(ident, category) == category, 'paired category')
                identities[ident] += 1
                if hit:
                    hexstr(t['packet_id'])
                    require(t['packet_bytes'] == 49508, 'complete packet byte length')
                    timing(t['native_admission'])
                    winning.append(t)
                else:
                    require(not ({'packet_id', 'packet_bytes', 'native_admission'} & set(t)),
                            'failed attempt cannot earn effective admission')
                if is_batch:
                    uint(t['overlapping_kernel_wall_ns'])
                    require('generation' not in t, 'batch does not sum overlapping process clocks')
                else:
                    timing(t['generation'])
                trials.append(t)
        ids = [t['packet_id'] for t in winning]
        require(len(ids) == len(set(ids)), 'duplicate admission within a fresh store')
        require(len(trials) == c['attempts'] and len(ids) == c['winners']
                == c['first_native_admissions'] == c['cold_packet_readbacks'], 'real denominator')
        require(c['exhausted'] == h - len(ids), 'exhausted searches included')
        require(sumtiming(t['native_admission'] for t in winning)
                == c['phases']['first_native_admission'], 'actual call admission totals')
        if not is_batch:
            require(sumtiming(t['generation'] for t in trials)
                    == c['phases']['all_attempt_generation'], 'all failed/successful generation charged')
        else:
            require(c['batch_process_clock_intervals'] == 1
                    and c['batch_includes_spawn_join_and_trial_records'] is True
                    and c['overlapping_trial_times_added_to_batch'] is False, 'exclusive whole batch clock')
            ws = c['worker_observations']
            require(len(ws) == c['batch_workers'] and
                    [w['worker'] for w in ws] == list(range(c['batch_workers'])), 'all native workers')
            require(len({w['thread_id'] for w in ws}) == c['batch_workers'], 'distinct worker threads')
            for w in ws:
                require(w['searches'] == len(range(w['worker'], h, c['batch_workers']))
                        and 0 <= w['started_offset_ns'] <= w['finished_offset_ns']
                        <= c['phases']['all_attempt_generation']['wall_ns'], 'worker coverage/interval')
        retained = c['retained_packets']
        require([p['id'] for p in retained] == ids, 'each winning packet cold read back once')
        for p in retained:
            hexstr(p['sha256'])
            require(p['bytes'] == 49508, 'cold readback full bytes')
            if is_batch:
                name = 'packets-v4/' + p['file']
                require(name not in packets_checked and PurePosixPath(name).name == p['id'] + '.packet',
                        'independent cohort archive entry')
                data = archive.read(name)
                require(len(data) == p['bytes'] and sha(data) == p['sha256'], 'archived packet SHA256/length')
                packets_checked.add(name)
        require(c['hot_active_before_close']['id'] == c['parent']
                and c['hot_active_before_close']['generation'] == 0, 'admission is not activation')
        require(c['cold_recovery_active']['id'] == (min(ids) if ids else c['parent'])
                and c['cold_recovery_selected_height'] == int(bool(ids))
                and c['cold_recovery_active']['generation'] == int(bool(ids)), 'ordinary cold recovery tip')
        pair = (r, h)
        observed = observation_stream(c)
        require(paired.setdefault(pair, observed) == observed, 'full paired observed input/packet identities')
        require(reported_streams.setdefault(pair, c['stream_sha256']) == c['stream_sha256'],
                'same recorded full proof stream hash')
        all_ids.update(ids)
        totals.update({'attempts': len(trials), 'first_admissions': len(ids),
                       'failed_attempts': len(trials) - len(ids), 'exhausted_searches': c['exhausted'],
                       'cold_readbacks': len(retained), 'producer_setup_calls': c['producer_setup_calls']})
        receipts.append({'round': r, 'horizon': h, 'reuse': reuse, 'strategy': c['strategy'],
                         'workers': c.get('batch_workers', 1), 'attempts': len(trials),
                         'first_admissions': len(ids), 'failed_attempts': len(trials)-len(ids),
                         'exhausted_searches': c['exhausted'], 'producer_setup_calls': c['producer_setup_calls'],
                         'phases': c['phases'], 'outer': outer,
                         'all_exclusive_phases': c['all_exclusive_phases'],
                         'recurring': c['recurring_producer_encode_admission']})
    require(summary['cohorts'] == count and summary['first_admission_calls'] == totals['first_admissions']
            and summary['distinct_fixture_packet_ids_across_paired_cohorts'] == len(all_ids), 'summary count binding')
    expected_repeats = 18 if is_v5 else 6 if is_batch else 4
    require(set(identities.values()) == {expected_repeats}, 'paired repetition count')
    if is_batch:
        require(packets_checked == {n for n in archive.namelist() if n.startswith('packets-v4/')},
                'all and only archived packets covered')
        pa = summary['payload_archive']
        require(pa['files'] == len(packets_checked) and pa['bytes'] == len(packets_checked) * 49508,
                'payload archive summary binding')
    # Compare original row summary clocks with independently parsed raw records.
    require(len(summary['groups']) == len(cohorts), 'summary group coverage')
    for c, g in zip(cohorts, summary['groups']):
        fields = ('round', 'strategy', 'attempts', 'winners', 'phases')
        if not is_batch:
            fields += ('reuse', 'exhausted')
        else:
            require(g['workers'] == c['batch_workers'], 'summary real CPU worker count')
        for key in fields:
            require(g[key] == c[key], ('summary raw group', key))
        for displayed, field in [('outer', 'observed_outer'), ('all_phases', 'all_exclusive_phases'),
                                 ('recurring', 'recurring_producer_encode_admission')]:
            require(g[displayed] == c[field], ('summary raw timing', displayed))
    result = {
        'raw_lines': len(rows), 'cohorts': count, 'complete': True,
        'totals': dict(totals), 'distinct_packet_ids': len(all_ids),
        'distinct_observed_trial_identities': len(identities),
        'observations_per_trial_identity': expected_repeats,
        'distinct_trial_partition': dict(collections.Counter(categories.values())),
        'raw_cohort_checks_passed': True, 'summary_raw_binding_passed': True,
        'paired_observed_identities_equal': True,
        'retained_packet_payloads_independently_sha256_checked': len(packets_checked),
        'independent_w1_arithmetic_recomputed': False, 'native_admission_reexecuted': False,
        'full_proof_stream_hash_independently_reconstructed': False,
        'cohort_receipts': receipts,
        'whole_cohort_outer_totals': sumtiming(c['observed_outer'] for c in cohorts),
        'whole_exclusive_phase_totals': sumtiming(c['all_exclusive_phases'] for c in cohorts),
        'global_settings_setup': begin['settings_setup'],
    }
    if is_v5:
        result['legal_constructors'] = list(ARMS)
        result['unsupported_constructors_excluded_from_winners'] = [ALL_ARMS[i] for i in range(13) if i not in LEGAL]
        result['global_support_matrix_material'] = begin['support_matrix_material']
        result['global_constructor_probe_total'] = sumtiming(p['preparation'] for p in begin['support_probe'])
        result['fixed_h256_reuse_comparisons'] = compare_h256(cohorts)
    return result, paired


def compare_h256(cohorts):
    selected = {(c['strategy'], c['reuse']): [] for c in cohorts if c['search_horizon'] == 256}
    for c in cohorts:
        if c['search_horizon'] == 256:
            selected[c['strategy'], c['reuse']].append(c)
    reference = sorted(selected['scalar-original', True], key=lambda c: c['round'])
    reference_cpu = sum(c['observed_outer']['process_cpu_ns'] for c in reference)
    out = []
    for arm in ARMS:
        yes = sorted(selected[arm, True], key=lambda c: c['round'])
        no = sorted(selected[arm, False], key=lambda c: c['round'])
        require(len(yes) == len(no) == 2, 'same fixed strategy in both rounds')
        wins = sum(c['winners'] for c in yes)
        outer_cpu = sum(c['observed_outer']['process_cpu_ns'] for c in yes)
        no_outer_cpu = sum(c['observed_outer']['process_cpu_ns'] for c in no)
        setup_yes = sum(c['phases']['producer_setup']['process_cpu_ns'] for c in yes)
        setup_no = sum(c['phases']['producer_setup']['process_cpu_ns'] for c in no)
        phase_cpu = {p: sum(c['phases'][p]['process_cpu_ns'] for c in yes) for p in PHASES}
        out.append({
            'strategy': arm, 'horizon': 256, 'reuse': True, 'rounds': [0, 1],
            'attempts': sum(c['attempts'] for c in yes), 'first_admissions': wins,
            'failed_attempts': sum(c['attempts'] - c['winners'] for c in yes),
            'exhausted_searches': sum(c['exhausted'] for c in yes),
            'outer_cpu_total_ns': outer_cpu,
            'outer_cpu_ms_per_first_admission': outer_cpu / wins / 1e6,
            'scalar_original_over_strategy_outer_cpu': reference_cpu / outer_cpu,
            'outer_cpu_reduction_vs_scalar_fraction': 1 - outer_cpu / reference_cpu,
            'outer_wall_ms_per_first_admission': sum(c['observed_outer']['wall_ns'] for c in yes) / wins / 1e6,
            'recurring_cpu_ms_per_first_admission': sum(c['recurring_producer_encode_admission']['process_cpu_ns'] for c in yes) / wins / 1e6,
            'phase_cpu_total_ns': phase_cpu,
            'outer_unphased_cpu_total_ns': outer_cpu - sum(phase_cpu.values()),
            'per_round': [{'round': c['round'], 'attempts': c['attempts'], 'first_admissions': c['winners'],
                           'outer_cpu_total_ns': c['observed_outer']['process_cpu_ns'],
                           'outer_cpu_ms_per_first_admission': c['observed_outer']['process_cpu_ns'] / c['winners'] / 1e6,
                           'scalar_original_over_strategy_outer_cpu': ref['observed_outer']['process_cpu_ns'] / c['observed_outer']['process_cpu_ns']}
                          for c, ref in zip(yes, reference)],
            'actual_setup_reuse_comparison': {
                'no_reuse_definition': 'one preparation per search (not per attempt)',
                'reuse_definition': 'one preparation for all 256 searches in each cohort',
                'no_reuse_setup_calls': sum(c['producer_setup_calls'] for c in no),
                'reuse_setup_calls': sum(c['producer_setup_calls'] for c in yes),
                'no_reuse_setup_cpu_total_ns': setup_no, 'reuse_setup_cpu_total_ns': setup_yes,
                'no_reuse_setup_cpu_ms_per_admission': setup_no / wins / 1e6,
                'reuse_setup_cpu_ms_per_admission': setup_yes / wins / 1e6,
                'no_reuse_outer_cpu_ms_per_admission': no_outer_cpu / wins / 1e6,
                'reuse_outer_cpu_ms_per_admission': outer_cpu / wins / 1e6,
                'no_reuse_over_reuse_outer_cpu': no_outer_cpu / outer_cpu,
            },
        })
    return out


def audit(spec, artifacts_dir, sources_dir):
    label, machine, elf_machine, artifact_id, expected_sha = spec
    path = artifacts_dir / f'legal-ticket-v5-{label}-974932be.zip'
    require(sha(path.read_bytes()) == expected_sha, 'exact original artifact bytes')
    sources = {p.name: p.read_bytes() for p in sources_dir.iterdir() if p.is_file()}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == 798, 'archive member coverage and uniqueness')
        inventory = []
        for name in names:
            require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                    'archive path')
            data = archive.read(name)  # zipfile verifies CRC on every original member.
            inventory.append({'path': name, 'bytes': len(data), 'sha256': sha(data)})
        by_path = {r['path']: r for r in inventory}
        source = parse(archive.read('source-before.json'))
        require(source['tested_commit'] == source['candidate'] == HEAD
                and source['tested_tree'] == TREE and source['kind'] == 'head'
                and source['tracked_worktree_verified'] is True, 'original CI source attestation')
        for name in ('source-after.json', 'source-after-v3.json', 'source-after-batch-v4.json'):
            require(parse(archive.read(name)) == source, ('source before/after binding', name))
        manifest = {}
        for line in archive.read('native-binaries.sha256').decode().splitlines():
            digest, name = line.split(maxsplit=1)
            manifest[PurePosixPath(name).name] = digest
        result, paired = {}, {}
        for folder, (driver, schema, count, budget) in VERSIONS.items():
            capture = parse(archive.read(folder + '/capture.json'))
            summary = parse(archive.read(folder + '/summary.json'))
            binary_name = driver + '.' + machine
            binary = archive.read(binary_name)
            binary_sha = by_path[binary_name]['sha256']
            require(binary[:6] == b'\x7fELF\x02\x01' and
                    struct.unpack_from('<H', binary, 18)[0] == elf_machine, 'native ELF architecture')
            require(binary_sha == capture['binary_sha256_before'] == capture['binary_sha256_after']
                    == manifest[binary_name], 'ELF capture and archive manifest binding')
            require(sources[driver + '.rs'] in binary and sources['Cargo.lock'] in binary,
                    'actual driver and Cargo.lock source bytes embedded in ELF')
            source_capture = capture['source']
            require(source_capture['commit'] == HEAD and source_capture['tree'] == TREE
                    and source_capture['example_sha256'] == sha(sources[driver + '.rs'])
                    and source_capture['lock_sha256'] == sha(sources['Cargo.lock'])
                    and source_capture['workspace_manifest_sha256'] == sha(sources['Cargo.toml']),
                    'source-file/driver/lock/manifest capture binding')
            require(capture['machine'] == machine and capture['exit_code'] == 0
                    and capture['timed_out'] is False and capture['stable_binary'] is True
                    and capture['stdout_within_bound'] is True and capture['timeout_seconds'] == budget + 10,
                    'successful bounded capture with unchanged binary')
            gz = archive.read(folder + '/stdout.jsonl.gz')
            require(sha(gz) == capture['stdout_gzip_sha256'] and len(gz) == capture['stdout_gzip_bytes'], 'gzip binding')
            raw = gzip.decompress(gz)
            require(sha(raw) == capture['stdout_uncompressed_sha256'] == summary['raw_uncompressed_sha256']
                    and len(raw) == capture['stdout_bytes'] and raw.endswith(b'\n'), 'uncompressed raw binding')
            lines = raw.splitlines()
            require(max(map(len, lines)) <= 2 * 1024 * 1024 and len(raw) <= 64 * 1024 * 1024,
                    'original output bounds')
            require(sha(archive.read(folder + '/stderr.log')) == capture['stderr_sha256'], 'stderr binding')
            rows = [parse(line) for line in lines]
            require(rows[0]['compiled_driver_sha256'] == source_capture['example_sha256']
                    and rows[0]['compiled_cargo_lock_sha256'] == source_capture['lock_sha256'],
                    'raw begin records embedded-source digests')
            require(summary['source'] == source and summary['native_capture'] == capture, 'summary capture/source binding')
            data, identities = validate_cohorts(rows, folder, archive, summary)
            cpu_s = capture['child_user_cpu_seconds'] + capture['child_system_cpu_seconds']
            require(cpu_s * 1e9 + 1000 >= data['whole_cohort_outer_totals']['process_cpu_ns']
                    and capture['elapsed_ns'] >= rows[-1]['wall_ns'] >= data['whole_cohort_outer_totals']['wall_ns'],
                    'full-process versus nested cohort budgets')
            data.update({
                'source_capture': source_capture, 'binary_sha256': binary_sha,
                'driver_bytes_embedded_in_elf': True, 'cargo_lock_bytes_embedded_in_elf': True,
                'capture_sha256': by_path[folder + '/capture.json']['sha256'],
                'stdout_sha256': sha(raw), 'stdout_gzip_sha256': sha(gz),
                'capture_exit_code': capture['exit_code'], 'capture_timed_out': capture['timed_out'],
                'capture_cpu_seconds': cpu_s, 'capture_wall_seconds': capture['elapsed_ns'] / 1e9,
                'capture_max_single_child_rss_kib': capture['child_max_rss_kib'],
                'capture_cpu_seconds_outside_cohort_outer': cpu_s - data['whole_cohort_outer_totals']['process_cpu_ns'] / 1e9,
                'capture_build': {k: capture[k] for k in ('build_profile', 'package_opt_levels',
                                                        'debug_info', 'incremental', 'build_jobs', 'rustc')},
            })
            result[folder] = data
            paired[folder] = identities
        require(paired['original-v3'] == paired['original-batch-v4'], 'legacy V3/V4 exact paired observed inputs')
        host = parse(archive.read('host.json'))
        require(host['machine'] == machine, 'host architecture')
        cpu = parse(archive.read('lscpu.json'))
        host['reported_cpu_model'] = next(v['data'] for v in cpu['lscpu'] if v['field'] == 'Model name:')
    return {
        'architecture': machine, 'artifact_id': artifact_id,
        'archive_path': str(path), 'archive_sha256': expected_sha,
        'archive_members': 798, 'all_member_crcs_checked': True,
        'source_before_after_consistent': True, 'source_record': source,
        'host_observation': host, 'experiments': result,
        'archive_inventory': inventory,
    }, paired


def main():
    parser = argparse.ArgumentParser(
        description='Independently audit original legal-ticket V5 artifacts at 974932be; no native ELF execution or W1 arithmetic replay.',
        epilog=('Requires both original ZIPs named legal-ticket-v5-x64-974932be.zip and '
                'legal-ticket-v5-arm64-974932be.zip. Also requires five companion source files: '
                'pon_legal_ticket_cost_v3.rs, pon_legal_ticket_batch_v4.rs, pon_legal_ticket_cost_v5.rs, '
                'Cargo.lock, and Cargo.toml. Exact source bytes are checked against the captures; '
                'drivers and Cargo.lock are also checked inside the original ELFs. '
                'No local repository checkout, toolchain, or network access is required.'))
    parser.add_argument('--artifacts-dir', type=Path, default=ROOT.parent,
                        help='Directory containing both original ZIPs (default: parent of script directory).')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'legal-ticket-v5-974932be-independent-audit.json',
                        help='Output JSON report path (default: named report beside this script).')
    parser.add_argument('--sources-dir', type=Path, default=ROOT / 'source',
                        help='Directory with the five companion source files (default: source/ beside this script).')
    args = parser.parse_args()
    outputs = [audit(spec, args.artifacts_dir.resolve(), args.sources_dir.resolve()) for spec in SPECS]
    require(outputs[0][1] == outputs[1][1], 'same paired observed input streams on both architectures')
    report = {
        'schema': 'independent-legal-ticket-v5-archive-audit-v1',
        'source_commit': HEAD, 'source_tree': TREE,
        'original_run': REPO + '/actions/runs/40845715652',
        'all_checks_passed': True,
        'both_architectures_same_observed_input_streams': True,
        'audit_script_sha256': sha(Path(__file__).read_bytes()),
        'source_files': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
                         for p in sorted(args.sources_dir.iterdir()) if p.is_file()],
        'results': [o[0] for o in outputs],
        'scope': [
            'This independent audit recalculates original raw counter, target-predicate, pairing, setup, first-admission and exclusive-clock accounting; it does not execute the native ELF.',
            'V5 has 144 fresh-store cohorts per architecture. Cross-strategy/reuse admissions repeat fixed input bytes and cannot be counted as independent network work or active-chain rewards.',
            'V5/V3 cold byte readback is an archived native observation with hashes; their packet payloads are not present. The native driver source and Cargo.lock bytes were found inside the exact captured ELF.',
            'All V4 packet files are independently checked against their original raw readback SHA256/length records. This is byte integrity, not cryptographic/native re-admission or W1 arithmetic replay.',
            'Source-before and all source-after records consistently attest one commit/tree. This audit does not reconstruct the entire 6184-entry tracked source tree or reproduce the compiler build.',
            'No independent W1 arithmetic is recomputed, no full proof stream hash is reconstructed, and no 1367-input ticket-first replay mapping is borrowed for V5.',
            'Reported H256 comparisons use one fixed strategy across both original rounds and total CPU divided by total first admissions; no per-round winner mixture is constructed.',
            'Setup reuse means one preparation per cohort instead of per search; unsuccessful trials remain charged. Support probes and final serialization/tempdir cleanup remain in complete-process capture, outside some cohort clocks.',
            'Recurring, exclusive phases and outer are nested cost scopes, not additive independent costs; native admission already includes native verification.',
            'The two architectures are different nonexclusive hosted machines. No same-host architecture effect, energy, GPU/ASIC cost, global minimum, real-chain reward, production readiness or transparent-proof cost is established.',
        ],
    }
    target = args.output.resolve()
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'pass': True, 'report': str(target), 'report_sha256': sha(target.read_bytes()),
                      'architectures': [{'architecture': r['architecture'],
                                         'v5_totals': r['experiments']['cost']['totals'],
                                         'distinct_v5_trials': r['experiments']['cost']['distinct_observed_trial_identities'],
                                         'distinct_v5_packets': r['experiments']['cost']['distinct_packet_ids'],
                                         'v4_payloads_checked': r['experiments']['original-batch-v4']['retained_packet_payloads_independently_sha256_checked']}
                                        for r in report['results']]}))


if __name__ == '__main__':
    main()
