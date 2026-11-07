#!/usr/bin/env python3
"""Recheck retained real DAA packets with the existing independent Python oracles.

This reader recomputes full PNW1 transcripts/products, header/ticket identities,
branch targets, median/future rules and accumulated required work. Native SQLite
admission/reopen and host/source provenance remain observations of the external
runner; this read-only program cannot turn those observations into authority.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'formal' / 'pon-nakamoto-v1'))
import contract_wire as wire
import reference
import work_oracle

NAMES = ('ordinary', 'lower-clamp', 'upper-clamp')
PACKET_BYTES = 318 + 2 + work_oracle.PROOF_BYTES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, low=0, high=(1 << 64) - 1):
    require(type(value) is int and low <= value <= high, name + ': bounded integer required')
    return value


def hexadecimal(value, size):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value) is not None,
            'canonical fixed-size lowercase hex required')
    return bytes.fromhex(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reject_number(_):
    raise ValueError('noninteger JSON number is outside this retained schema')


def load_report(raw):
    return json.loads(raw, object_pairs_hook=wire.unique, parse_float=reject_number,
                      parse_constant=reject_number)


def analyze_report(report, packet_bytes):
    require(report['schema'] in ('pon-native-daa-bounds-v1', 'pon-native-daa-fork-choice-v1'),
            'unsupported native DAA report')
    fork_choice = report['schema'] == 'pon-native-daa-fork-choice-v1'
    exact = {'interval': 16, 'spacing_seconds': 10, 'median_window': 11,
             'future_skew_seconds': 120, 'desired_span_seconds': 150,
             'clamped_span_lower_seconds': 38, 'clamped_span_upper_seconds': 600}
    for key, value in exact.items():
        require(integer(report[key], key) == value, 'original DAA profile changed: ' + key)
    for key in ('default_consensus_rules_changed', 'wall_clock_cadence_measured',
                'attacker_work_fraction_measured', 'timestamp_attack_profitability_measured',
                'public_network_qualification'):
        require(report[key] is False, 'unsupported qualification: ' + key)
    controls = ('longer_lower_work_replaces_harder_branch', 'equal_work_replaces_active_tip') if fork_choice else (
        'lower_work_branch_replaces_harder_branch',)
    for key in controls:
        require(report[key] is False, 'unsupported fork-choice claim: ' + key)
    require(report['logical_validation_clock_schedule'] is True, 'required retained logical-clock scope')
    if not fork_choice:
        require(report['same_packet_clock_retry_admitted'] is True, 'required exact-packet retry scope')
    network = hexadecimal(report['network'], 32)
    parameters = hexadecimal(report['parameters'], 32)
    genesis = hexadecimal(report['genesis'], 32)
    genesis_time = integer(report['genesis_timestamp'], 'genesis timestamp', 1)
    limit = int.from_bytes(hexadecimal(report['pow_limit'], 32), 'big')
    require(limit == (1 << 255) - 1, 'original pow_limit changed')
    genesis_work = int.from_bytes(hexadecimal(report['genesis_chainwork_hex'], 64), 'big')
    require(genesis_work == 0, 'genesis cannot acquire packet work')
    rows = report['records']
    counts = ({'common-compressed': 31, 'lower-clamp': 16, 'upper-clamp': 16,
               'equal-work-hard-sibling': 2, 'longer-easier': 2} if fork_choice else
              {'common-compressed': 31, 'ordinary': 17, 'lower-clamp': 17, 'upper-clamp': 17,
               'time-boundary-negative': 2, 'future-clock-retry': 1})
    require(isinstance(rows, list) and len(rows) == sum(counts.values()), 'complete finite ' + str(sum(counts.values())) + '-observation grid required')
    require(Counter(row['schedule'] for row in rows) == counts, 'schedule observations were dropped or duplicated')
    admitted = {genesis: {'height': 0, 'timestamp': genesis_time, 'target': limit.to_bytes(32, 'big'),
                         'work': genesis_work, 'parent': None}}
    grid, proofs, seen_rows, negatives = {}, {}, set(), []

    def lineage(parent):
        chain = []
        while parent is not None:
            require(parent in admitted, 'missing previously admitted exact branch parent')
            chain.append(admitted[parent])
            parent = admitted[parent]['parent']
        return chain

    def expected_target(chain, height):
        parent = chain[0]
        if height % 16:
            return int.from_bytes(parent['target'], 'big')
        first = next(item for item in chain if item['height'] == height - 16)
        return reference.retarget(int.from_bytes(parent['target'], 'big'), first['timestamp'],
                                  parent['timestamp'], 16, 10, limit)

    for row in rows:
        identifier = hexadecimal(row['id'], 32)
        filename = 'packets/' + identifier.hex() + '.pnk'
        require(row['packet_file'] == filename and filename in packet_bytes, 'exact retained packet required')
        raw = packet_bytes[filename]
        require(isinstance(raw, bytes) and len(raw) == PACKET_BYTES, 'complete empty-transaction packet length required')
        require(integer(row['packet_bytes'], 'packet length') == len(raw) and sha(raw) == row['packet_sha256'],
                'packet bytes changed after native observation')
        require(raw[318:320] == b'\x00\x00', 'DAA schedule must retain zero transaction count')
        header_raw, proof = raw[:318], raw[320:]
        require(hexadecimal(row['header_hex'], 318) == header_raw, 'header observation differs from actual packet')
        header = wire.header_decode(header_raw)
        require(wire.header_encode(header) == header_raw, 'noncanonical header')
        require(header['network'] == network and header['parameters'] == parameters, 'header context mismatch')
        for name in ('height', 'timestamp', 'nonce'):
            require(integer(row[name], name) == header[name], name + ' differs from exact header')
        for name in ('parent', 'target'):
            require(hexadecimal(row[name], 32) == header[name], name + ' differs from exact header')
        require(integer(row['attempts'], 'reported complete proof attempts', 1, 4096) == header['nonce'] + 1,
                'attempt count differs from bounded nonce-zero native search')
        require(integer(row['proof_bytes'], 'proof length') == work_oracle.PROOF_BYTES
                and sha(proof) == row['proof_sha256'], 'proof bytes changed')
        require(hexadecimal(row['trace'], 32) == proof[-32:], 'trace differs from retained PNW1')
        require(wire.H('block', header_raw, proof[-32:]) == identifier, 'block identity mismatch')
        require(row['complete_native_work_verification'] is True, 'native full verification was not observed')
        # This is only the existing cheap grammar/task/ticket filter. Full scalar
        # transcript and product replay occurs after all record consistency checks.
        challenge = wire.H('challenge', header_raw)
        work_oracle.precheck(challenge, header['work_task'], header['target'], proof)
        if identifier in proofs:
            require(proofs[identifier] == (challenge, header['work_task'], header['target'], proof),
                    'same block identity acquired changed proof bytes')
        proofs[identifier] = (challenge, header['work_task'], header['target'], proof)
        chain = lineage(header['parent'])
        require(header['height'] == chain[0]['height'] + 1, 'branch height mismatch')
        target = int.from_bytes(header['target'], 'big')
        require(target == expected_target(chain, header['height']), 'branch retarget differs from independent integer arithmetic')
        required_work = reference.work(target)
        require(int.from_bytes(hexadecimal(row['required_work_hex'], 64), 'big') == required_work,
                'packet work must use expected target rather than lucky ticket')
        recent = [item['timestamp'] for item in chain[:11]]
        require(row['ancestor_timestamps_parent_first'] == recent, 'median ancestry is not the retained branch')
        median = sorted(recent)[len(recent) // 2]
        require(integer(row['median_time_past'], 'median') == median, 'median mismatch')
        now = integer(row['observed_now'], 'observed clock')
        state = reference.timestamp_state(header['timestamp'], list(reversed(recent)), now, 120)
        outcome = row['admission']
        key = (identifier, now, outcome['kind'])
        require(key not in seen_rows, 'duplicate observation cannot increase the cohort')
        seen_rows.add(key)
        if outcome['kind'] == 'admitted':
            require(state == 'admissible', 'admitted timestamp fails original median/future rules')
            work = chain[0]['work'] + required_work
            require(int.from_bytes(hexadecimal(outcome['cumulative_required_work_hex'], 64), 'big') == work,
                    'cumulative branch work mismatch')
            require(identifier not in admitted, 'duplicate admission does not add work')
            admitted[identifier] = {**header, 'work': work}
        else:
            error = {'invalid-median': 'TIME', 'deferred-future': 'TIME_DEFERRED'}.get(state)
            require(outcome['kind'] == 'rejected' and outcome['error'] == error and error is not None,
                    'negative record does not fail its claimed original time boundary')
            negatives.append(row)
        schedule = row['schedule']
        if schedule == 'common-compressed' or schedule in NAMES:
            grid_key = (schedule, header['height'])
            require(grid_key not in grid and outcome['kind'] == 'admitted', 'each declared schedule block must be admitted once')
            grid[grid_key] = row
            if schedule == 'common-compressed':
                require(1 <= header['height'] <= 31, 'common period height')
                offset, clock = header['height'], header['height'] * 10
            else:
                height = header['height']
                require(32 <= height <= (47 if fork_choice else 48), 'branch period height')
                offset = height * 10 if schedule == 'ordinary' else height
                if schedule == 'upper-clamp':
                    offset = {32: 27, 47: 627, 48: 628}.get(height, height * 10)
                clock = 508 if height == 48 else 507 if schedule == 'upper-clamp' and height == 47 else height * 10
            require(header['timestamp'] == genesis_time + offset and now == genesis_time + clock,
                    'declared finite logical timestamp/clock schedule changed')
        elif fork_choice:
            require(outcome['kind'] == 'admitted', 'fork-choice control requires full admitted packets')
            height = header['height']
            if schedule == 'equal-work-hard-sibling':
                require(height == 48 and header['timestamp'] == genesis_time + 48,
                        'hard siblings must share height and timestamp')
                parent = hexadecimal(grid[('lower-clamp', 47)]['id'], 32)
            else:
                require(schedule == 'longer-easier' and height in (48, 49), 'unknown fork-choice schedule')
                require(header['timestamp'] == genesis_time + 580 + height, 'longer branch timestamp changed')
                parent_key = ('upper-clamp', 47) if height == 48 else ('longer-easier', 48)
                parent = hexadecimal(grid[parent_key]['id'], 32)
                require((schedule, height) not in grid, 'duplicate longer-branch height')
                grid[(schedule, height)] = row
            require(header['parent'] == parent and now == genesis_time + 509,
                    'fork-choice packet changed its declared branch or logical clock')
    require(set(packet_bytes) == {'packets/' + identifier.hex() + '.pnk' for identifier in proofs},
            'missing or extra retained packet file')
    if fork_choice:
        return analyze_fork_choice(report, rows, admitted, proofs, grid)
    require(len(proofs) == 84 and len(admitted) == 84, 'unique proof/accepted-packet denominator mismatch')
    period_target = int.from_bytes(hexadecimal(report['branch_period_target'], 32), 'big')
    require(period_target * 4 < limit, 'upper boundary must be visible below pow_limit')
    require(period_target == int.from_bytes(admitted[hexadecimal(grid[('ordinary', 47)]['id'], 32)]['target'], 'big'),
            'declared period target mismatch')
    expected = [period_target, max(1, period_target * 38 // 150), period_target * 4]
    require(len(report['next_targets']) == 3, 'three independent next-target observations required')
    for name, target, claim in zip(NAMES, expected, report['next_targets']):
        require(claim['schedule'] == name and int.from_bytes(hexadecimal(claim['target'], 32), 'big') == target,
                'next target does not reach its declared original clamp')
        require(hexadecimal(grid[(name, 48)]['target'], 32) == target.to_bytes(32, 'big'), 'actual next block uses a different target')
        require(int.from_bytes(hexadecimal(claim['required_work_hex'], 64), 'big') == reference.work(target),
                'next required work mismatch')
    deferred = next(row for row in negatives if row['admission']['error'] == 'TIME_DEFERRED')
    at_median = next(row for row in negatives if row['admission']['error'] == 'TIME')
    retry = next(row for row in rows if row['schedule'] == 'future-clock-retry')
    require(deferred['timestamp'] == deferred['observed_now'] + 121
            and at_median['timestamp'] == at_median['median_time_past'], 'exact time boundaries not retained')
    require(retry['id'] == deferred['id'] and retry['packet_sha256'] == deferred['packet_sha256']
            and retry['observed_now'] == deferred['observed_now'] + 1
            and retry['admission']['kind'] == 'admitted', 'future retry must use the exact original proof one clock second later')
    require(len(report['activations']) == 3, 'complete activation order required')
    last_work = -1
    for ordinal, (name, activation) in enumerate(zip(('upper-clamp', 'ordinary', 'lower-clamp'), report['activations']), 32):
        stats = activation['stats']
        require(activation['schedule'] == name and stats['tip'] == grid[(name, 48)]['id'], 'activation does not select its actual branch')
        header = admitted[hexadecimal(stats['tip'], 32)]
        require(int.from_bytes(hexadecimal(stats['chainwork_hex'], 64), 'big') == header['work'] > last_work,
                'each actual activation must strictly increase required chainwork')
        require(integer(stats['height'], 'active height') == 48 and integer(stats['generation'], 'active generation') == ordinal,
                'native activation height/generation mismatch')
        require(hexadecimal(stats['state_root'], 32) == header['state'], 'active state root differs from the selected header')
        last_work = header['work']
    selected, reopened = report['selected_before_negative_checks'], report['after_authenticated_reopen']
    require(selected == report['activations'][-1]['stats'], 'negative checks started from another active branch')
    require(set(selected) == set(reopened) and all(selected[key] == reopened[key] for key in selected if key != 'stored_blocks'),
            'retained reopen changed the selected native state/generation/work')
    require(selected['stored_blocks'] == 83 and reopened['stored_blocks'] == 84,
            'rejected blocks cannot be stored; one deferred retry adds exactly one packet')
    verify_proofs(proofs)
    return {
        'schema': 'pon-native-daa-bounds-reader-v1', 'record_and_oracle_consistency': 'PASS',
        'observations': len(rows), 'unique_full_python_verified_proofs': len(proofs),
        'unique_native_admitted_packets_observed': len(admitted) - 1,
        'native_time_rejections_observed': len(negatives),
        'next_targets': report['next_targets'], 'selected_required_chainwork': last_work,
        'reader_performed_native_admission': False, 'reader_reopened_native_database': False,
        'host_and_source_provenance_checked_by_reader': False,
        'full_python_transcript_and_product_recomputed': True,
        'proof_hardness_or_timestamp_attack_profitability_qualified': False,
        'public_network_qualification': False,
    }


def verify_proofs(proofs):
    for identifier, args in proofs.items():
        try:
            work_oracle.verify(*args)
        except ValueError as error:
            raise ValueError('full Python PNW1 replay ' + identifier.hex() + ': ' + str(error)) from error


def analyze_fork_choice(report, rows, admitted, proofs, grid):
    require(len(proofs) == 67 and len(admitted) == 68, 'unique fork-choice proof/admission denominator mismatch')
    period_target = int.from_bytes(hexadecimal(report['branch_period_target'], 32), 'big')
    limit = int.from_bytes(hexadecimal(report['pow_limit'], 32), 'big')
    require(period_target * 4 < limit, 'fork-choice upper clamp must remain below pow_limit')
    for name in ('lower-clamp', 'upper-clamp'):
        require(hexadecimal(grid[(name, 47)]['target'], 32) == period_target.to_bytes(32, 'big'),
                'fork-choice period target mismatch')
    siblings = [row for row in rows if row['schedule'] == 'equal-work-hard-sibling']
    sibling_ids = {hexadecimal(row['id'], 32) for row in siblings}
    hard_target = max(1, period_target * 38 // 150)
    require(len(sibling_ids) == 2 and all(int.from_bytes(admitted[key]['target'], 'big') == hard_target
                                       for key in sibling_ids), 'two genuine equal-target hard siblings required')
    longer = report['longer_easier_selected']
    selected = report['shorter_harder_selected']
    chosen_id = hexadecimal(selected['tip'], 32)
    equal_id = hexadecimal(report['equal_work_candidate'], 32)
    easy_id = hexadecimal(longer['tip'], 32)
    require(easy_id == hexadecimal(grid[('longer-easier', 49)]['id'], 32), 'longer branch selection mismatch')
    require({chosen_id, equal_id} == sibling_ids and equal_id < chosen_id,
            'selected hard sibling must oppose recovery id ordering')
    hard, easy = admitted[chosen_id], admitted[easy_id]
    require(hard['work'] == admitted[equal_id]['work'] and hard['parent'] == admitted[equal_id]['parent'],
            'equal-work candidate is not the actual same-parent sibling')
    require(hard['height'] == 48 < easy['height'] == 49 and hard['work'] > easy['work'],
            'shorter harder branch must strictly outwork the longer easier branch')
    require(int.from_bytes(easy['target'], 'big') == period_target * 4,
            'longer branch must retain actual upper-clamp target')
    for stats, header, generation in ((longer, easy, 32), (selected, hard, 33)):
        require(integer(stats['height'], 'active height') == header['height']
                and integer(stats['generation'], 'active generation') == generation,
                'fork-choice active height or generation mismatch')
        require(int.from_bytes(hexadecimal(stats['chainwork_hex'], 64), 'big') == header['work'],
                'fork-choice selected cumulative work mismatch')
        require(hexadecimal(stats['state_root'], 32) == header['state'], 'fork-choice selected state-root mismatch')
        require(integer(stats['stored_blocks'], 'stored blocks') == 68, 'all admitted fork-choice packets must remain stored')
    attempts = report['non_winning_candidates']
    require(isinstance(attempts, list) and len(attempts) == 4, 'both candidates must be retried before and after reopen')
    for attempt, (stage, candidate) in zip(attempts, (
            ('before-reopen', easy_id), ('before-reopen', equal_id),
            ('after-reopen', easy_id), ('after-reopen', equal_id))):
        require(attempt['stage'] == stage and hexadecimal(attempt['candidate'], 32) == candidate,
                'non-winning activation grid changed')
        require(hexadecimal(attempt['returned_tip'], 32) == chosen_id and attempt['stats'] == selected,
                'lower or equal work changed the recorded active state or generation')
    require(report['after_authenticated_reopen'] == selected, 'authenticated reopen changed recorded active state')
    verify_proofs(proofs)
    return {
        'schema': 'pon-native-daa-fork-choice-reader-v1', 'record_and_oracle_consistency': 'PASS',
        'observations': len(rows), 'unique_full_python_verified_proofs': len(proofs),
        'unique_native_admitted_packets_observed': len(admitted) - 1,
        'longer_easier_height': easy['height'], 'longer_easier_required_chainwork': easy['work'],
        'shorter_harder_height': hard['height'], 'shorter_harder_required_chainwork': hard['work'],
        'non_winning_activation_attempts_observed': len(attempts),
        'selected_larger_id_equal_work_sibling': True,
        'reader_performed_native_admission': False, 'reader_reopened_native_database': False,
        'host_and_source_provenance_checked_by_reader': False,
        'full_python_transcript_and_product_recomputed': True,
        'proof_hardness_or_timestamp_attack_profitability_qualified': False,
        'public_network_qualification': False,
    }


def read_bounded(path, maximum):
    require(not path.is_symlink(), 'retained evidence cannot use a symbolic link')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'retained file exceeds finite evidence schema')
    return raw


def analyze(raw_dir, expected_sha256, report_kind='bounds'):
    hexadecimal(expected_sha256, 32)
    require(report_kind in ('bounds', 'fork-choice'), 'unsupported retained report kind')
    raw = read_bounded(raw_dir / ('daa-' + report_kind + '.json'), 2 * 1024 * 1024)
    require(sha(raw) == expected_sha256, 'exact externally recorded DAA report digest required')
    report = load_report(raw)
    require(report['schema'] == 'pon-native-daa-' + report_kind + '-v1', 'report kind does not match retained schema')
    directory = raw_dir / 'packets'
    require(not directory.is_symlink(), 'packet directory cannot be a symbolic link')
    files = list(directory.iterdir())
    require(len(files) == (67 if report_kind == 'fork-choice' else 84), 'complete bounded native packet inventory required')
    packets = {}
    for path in files:
        require(re.fullmatch('[0-9a-f]{64}\\.pnk', path.name) is not None, 'unexpected retained packet file')
        packets['packets/' + path.name] = read_bounded(path, PACKET_BYTES)
    result = analyze_report(report, packets)
    result['report_sha256'] = sha(raw)
    result['packet_identities'] = {name: {'sha256': sha(data), 'bytes': len(data)} for name, data in sorted(packets.items())}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-report-sha256', required=True)
    parser.add_argument('--report-kind', choices=('bounds', 'fork-choice'), default='bounds')
    args = parser.parse_args()
    try:
        result = analyze(args.raw_dir, args.expected_report_sha256, args.report_kind)
    except (OSError, ValueError, TypeError, KeyError, StopIteration) as error:
        print(json.dumps({'schema': 'pon-native-daa-' + args.report_kind + '-reader-v1', 'result': 'FAIL', 'error': str(error)}))
        return 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
