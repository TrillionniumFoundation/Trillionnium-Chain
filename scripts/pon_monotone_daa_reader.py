#!/usr/bin/env python3
"""Recompute the separate strict-monotone native DAA experiment.

The legacy negative-endpoint reader retains its exact acceptance contract. This
reader shares only packet/domain/witness framing, head/binding checks and scalar
W1/DAA primitives with it. Every declared altered timestamp is independently
recomputed as its actual parent's timestamp plus one; all three endpoint spans
must be +15, clamped to 38 under the unchanged periodic rule.

A PASS checks all 114 retained complete W1 products and the declared finite
trajectory. Native application admission, activation and cold reopen remain
external runner observations. No live network, physical attack cost, quantum
profitability, CP/CG/CQ or production qualification follows from this replay.
"""
import argparse
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import pon_joint_daa_reader as legacy

require = legacy.require
integer = legacy.integer
hexadecimal = legacy.hexadecimal
sha = legacy.sha
load_report = legacy.load_report
wire = legacy.wire
reference = legacy.reference
work_oracle = legacy.work_oracle
fields = legacy.fields
decode_packet = legacy.decode_packet
check_head = legacy.check_head
check_bindings = legacy.check_bindings
read_bounded = legacy.read_bounded

SCHEMA = 'pon-native-monotone-daa-v1'
READER_SCHEMA = 'pon-native-monotone-daa-reader-v1'
GENESIS_TIME = legacy.GENESIS_TIME
PROFILES = legacy.PROFILES
ALTERED = 'strict-monotone-compressed'
COHORT = ([('common', height) for height in range(1, 16)]
          + [(name, height) for height in range(16, 65) for name in ('ordinary', ALTERED)]
          + [('ordinary', 65)])
PACKET_COUNT = legacy.PACKET_COUNT
MAX_PACKET_BYTES = legacy.MAX_PACKET_BYTES
REPORT_FIELDS = legacy.REPORT_FIELDS | {'parent_monotonicity_enforced_by_schedule'}
ROW_FIELDS = legacy.ROW_FIELDS
RETARGET_FIELDS = legacy.RETARGET_FIELDS


def analyze_report(report, packet_bytes):
    fields(report, REPORT_FIELDS, 'monotone DAA report')
    require(report['schema'] == SCHEMA, 'unsupported native monotone DAA report')
    require(report['backend'] in PROFILES and report['header_profile'] == PROFILES[report['backend']]
            and report['work_profile'] == 'PNW1', 'native backend/header/work profile mismatch')
    profile = report['header_profile']
    exact = {'genesis_timestamp': GENESIS_TIME, 'interval': 16, 'spacing_seconds': 10,
             'median_window': 11, 'future_skew_seconds': 120, 'desired_span_seconds': 150,
             'clamped_span_lower_seconds': 38, 'clamped_span_upper_seconds': 600}
    for key, value in exact.items():
        require(integer(report[key], key) == value, 'fixed monotone DAA experiment changed: ' + key)
    for key in ('default_consensus_rules_changed',
                'wall_clock_cadence_measured', 'attacker_work_fraction_measured',
                'quantum_attack_profitability_measured', 'public_network_qualification'):
        require(report[key] is False, 'unsupported qualification or activation-clock claim: ' + key)
    for key in ('shorter_higher_work_branch_selected', 'logical_validation_clock_schedule',
                'parent_monotonicity_enforced_by_schedule'):
        require(report[key] is True, 'required finite native observation scope: ' + key)
    require(report['activation_observed_clock_api'] is True,
            'native activation observed-clock API must match the monotone experiment')
    require(report['growth_activation_clock_checked'] is (profile == 'PGH2'),
            'growth activation clock observation must match the actual owner profile')
    network = hexadecimal(report['network'], 32)
    parameters = hexadecimal(report['parameters'], 32)
    genesis = hexadecimal(report['genesis'], 32)
    initial = int.from_bytes(hexadecimal(report['initial_target'], 32), 'big')
    limit = int.from_bytes(hexadecimal(report['pow_limit'], 32), 'big')
    require(initial == limit == (1 << 255) - 1, 'original initial target and pow_limit changed')
    genesis_work = int.from_bytes(hexadecimal(report['genesis_chainwork_hex'], 64), 'big')
    require(genesis_work == 0, 'genesis cannot acquire packet work')
    rows = report['records']
    require(type(rows) is list and len(rows) == PACKET_COUNT,
            'complete fixed 114-record native trajectory required')
    require(type(packet_bytes) is dict and len(packet_bytes) == PACKET_COUNT,
            'complete bounded 114-packet inventory required')
    admitted = {genesis: {'height': 0, 'timestamp': GENESIS_TIME,
                         'target': initial.to_bytes(32, 'big'), 'work': 0, 'parent': None}}
    grid, proofs, decoded, computed_retargets = {}, {}, {}, []
    attempts = 0

    def lineage(parent):
        chain = []
        while parent is not None:
            require(parent in admitted, 'missing previously admitted exact branch parent')
            chain.append(admitted[parent])
            parent = admitted[parent]['parent']
        return chain

    for row, (schedule, height) in zip(rows, COHORT):
        fields(row, ROW_FIELDS, 'native packet record')
        require(row['schedule'] == schedule and integer(row['height'], 'height') == height,
                'fixed trajectory order, schedule or height changed')
        identifier = hexadecimal(row['id'], 32)
        filename = 'packets/' + identifier.hex() + '.pnk'
        require(row['packet_file'] == filename and filename in packet_bytes, 'exact retained packet required')
        raw = packet_bytes[filename]
        require(type(raw) is bytes and integer(row['packet_bytes'], 'packet bytes') == len(raw)
                and hexadecimal(row['packet_sha256'], 32).hex() == sha(raw),
                'packet bytes changed after native observation')
        packet = decode_packet(profile, raw)
        header, header_raw, proof = packet['header'], packet['header_raw'], packet['proof']
        require(hexadecimal(row['header_hex'], len(header_raw)) == header_raw, 'header observation differs from actual packet')
        require(packet['id'] == identifier, 'block identity mismatch for the selected header domain')
        require(hexadecimal(row['challenge'], 32) == packet['challenge'], 'challenge differs from selected header domain')
        require(header['network'] == network and header['parameters'] == parameters, 'header context mismatch')
        require(header['transactions'] == wire.sequence_root('transactions', []), 'empty transaction root mismatch')
        for name in ('height', 'timestamp', 'nonce'):
            require(integer(row[name], name) == header[name], name + ' differs from exact header')
        for name in ('parent', 'target'):
            require(hexadecimal(row[name], 32) == header[name], name + ' differs from exact header')
        attempt = integer(row['attempts'], 'reported complete proof attempts', 1, 4096)
        require(attempt == header['nonce'] + 1, 'attempt count differs from bounded nonce-zero native search')
        attempts += attempt
        require(integer(row['proof_bytes'], 'proof bytes') == work_oracle.PROOF_BYTES
                and hexadecimal(row['proof_sha256'], 32).hex() == sha(proof), 'proof bytes changed')
        require(hexadecimal(row['trace'], 32) == proof[-32:], 'trace differs from retained PNW1')
        require(row['complete_native_work_verification'] is True, 'native full work verification scope was removed')
        expected_parent = (genesis if height == 1 else grid[('common', height - 1)]
                           if schedule == 'common' else grid[('common', 15)]
                           if height == 16 else grid[(schedule, height - 1)])
        require(header['parent'] == expected_parent, 'exact common/fork parent lineage changed')
        chain = lineage(header['parent'])
        require(header['height'] == chain[0]['height'] + 1, 'branch height mismatch')
        target = int.from_bytes(header['target'], 'big')
        parent_target = int.from_bytes(chain[0]['target'], 'big')
        expected_target = parent_target
        if height % 16 == 0:
            require(len(chain) >= 16 and chain[15]['height'] == height - 16, 'retarget branch window missing')
            first, last = chain[15]['timestamp'], chain[0]['timestamp']
            expected_target = reference.retarget(parent_target, first, last, 16, 10, limit)
            if schedule == ALTERED and height > 16:
                require(last - first == 15, 'three strict positive 15-second endpoint spans required')
                computed_retargets.append({
                    'height': height, 'first_timestamp': first, 'last_timestamp': last,
                    'signed_span_seconds': str(last - first), 'saturating_span_seconds': max(0, last - first),
                    'effective_span_seconds': min(600, max(38, max(1, last - first))),
                    'parent_target': parent_target.to_bytes(32, 'big').hex(),
                    'next_target': expected_target.to_bytes(32, 'big').hex()})
        require(target == expected_target, 'branch retarget differs from independent integer arithmetic')
        weight = reference.work(target)
        require(int.from_bytes(hexadecimal(row['required_work_hex'], 64), 'big') == weight,
                'packet work must use linear required_work of the expected target')
        recent = [item['timestamp'] for item in chain[:11]]
        claimed_recent = row['ancestor_timestamps_parent_first']
        require(type(claimed_recent) is list and all(type(value) is int for value in claimed_recent)
                and claimed_recent == recent, 'median ancestry is not the exact retained branch')
        median = sorted(recent)[len(recent) // 2]
        require(integer(row['median_time_past'], 'median') == median, 'median mismatch')
        now = integer(row['observed_now'], 'observed clock')
        timestamp = (GENESIS_TIME + height * 10 if schedule != ALTERED
                     else chain[0]['timestamp'] + 1)
        require(header['timestamp'] > chain[0]['timestamp'],
                'strict parent timestamp increase required for every retained branch')
        require(header['timestamp'] == timestamp and now == GENESIS_TIME + height * 10,
                'fixed logical parent-plus-one timestamp/clock schedule changed')
        require(reference.timestamp_state(header['timestamp'], list(reversed(recent)), now, 120) == 'admissible',
                'admitted timestamp fails original median/future rules')
        outcome = row['admission']
        fields(outcome, {'kind', 'cumulative_required_work_hex'}, 'native admission observation')
        total = chain[0]['work'] + weight
        require(outcome['kind'] == 'admitted'
                and int.from_bytes(hexadecimal(outcome['cumulative_required_work_hex'], 64), 'big') == total,
                'cumulative branch work or admission outcome mismatch')
        require(identifier not in admitted, 'duplicate packet cannot increase the trajectory or work')
        # Cheap filters are deliberately after branch/context arithmetic. Full
        # scalar replay remains mandatory below before any PASS can be returned.
        work_oracle.precheck(packet['challenge'], header['work_task'], header['target'], proof)
        admitted[identifier] = {**header, 'work': total}
        grid[(schedule, height)] = identifier
        proofs[identifier] = (packet['challenge'], header['work_task'], header['target'], proof)
        decoded[identifier] = packet
    require(set(packet_bytes) == {'packets/' + identifier.hex() + '.pnk' for identifier in proofs},
            'missing or extra retained packet identity')
    require(len(proofs) == PACKET_COUNT and len(admitted) == PACKET_COUNT + 1,
            'unique verified/admitted packet denominator mismatch')
    retargets = report['retargets']
    require(type(retargets) is list and len(retargets) == 3, 'all three repeated retarget observations required')
    for claimed, expected in zip(retargets, computed_retargets):
        fields(claimed, RETARGET_FIELDS, 'retarget observation')
        for key in ('height', 'first_timestamp', 'last_timestamp', 'saturating_span_seconds', 'effective_span_seconds'):
            integer(claimed[key], 'retarget ' + key)
        for key in ('parent_target', 'next_target'):
            hexadecimal(claimed[key], 32)
        require(type(claimed['signed_span_seconds']) is str and claimed == expected,
                'retarget observation differs from actual positive endpoint lineage')
    require([item['signed_span_seconds'] for item in computed_retargets] == ['15', '15', '15'],
            'fixed three-period endpoint trajectory changed')
    tips = [grid[('ordinary', 65)], grid[(ALTERED, 64)]]
    totals = [admitted[tip]['work'] for tip in tips]
    require(totals == [130, 793], 'fixed linear chainwork totals changed')
    for name, tip, total in zip(('ordinary', 'altered'), tips, totals):
        require(hexadecimal(report[name + '_tip'], 32) == tip
                and int.from_bytes(hexadecimal(report[name + '_chainwork_hex'], 64), 'big') == total,
                'reported branch tip or chainwork mismatch')
    activations = report['activations']
    require(type(activations) is list and len(activations) == 2, 'complete two-branch activation order required')
    last_work = genesis_work
    for generation, (head, tip, events) in enumerate(zip(activations, tips, (65, 164)), 1):
        check_head(head, profile, report, admitted, tip, generation, events)
        require(admitted[tip]['work'] > last_work, 'actual activation must strictly increase chainwork')
        last_work = admitted[tip]['work']
        require(all(item['timestamp'] <= GENESIS_TIME + 650 + 120 for item in lineage(tip)),
                'retained activation history exceeds its logical future bound')
    require(admitted[tips[1]]['height'] < admitted[tips[0]]['height'] and totals[1] > totals[0],
            'selected branch must be shorter and strictly heavier')
    check_head(report['after_cold_reopen'], profile, report, admitted, tips[1], 2, 164)
    require(report['after_cold_reopen'] == activations[-1], 'cold reopen changed selected native state/generation/work')
    probe_count = check_bindings(report['binding_rejections'], profile, decoded[tips[1]])
    for identifier, args in proofs.items():
        try:
            work_oracle.verify(*args)
        except ValueError as error:
            raise ValueError('full Python PNW1 replay ' + identifier.hex() + ': ' + str(error)) from error
    return {
        'schema': READER_SCHEMA, 'record_and_oracle_consistency': 'PASS',
        'backend': report['backend'], 'header_profile': profile,
        'observations': len(rows), 'unique_full_python_verified_proofs': len(proofs),
        'unique_native_admitted_packets_observed': len(admitted) - 1,
        'native_time_rejections_observed': 0, 'complete_changed_header_probes': probe_count,
        'permissive_filter_full_transcript_rejections': probe_count,
        'permissive_filter_is_consensus_target': False,
        'nonce_implied_native_search_attempts': attempts,
        'reader_replayed_all_failed_nonce_attempts': False,
        'retargets': computed_retargets, 'ordinary_required_chainwork': totals[0],
        'selected_required_chainwork': totals[1], 'selected_height': 64, 'ordinary_height': 65,
        'growth_witness_hashes_recomputed': len(proofs) if profile == 'PGH2' else 0,
        'reader_verified_aam1_account_proofs': False,
        'reader_replayed_native_task_eligibility_or_m06_execution': False,
        'reader_performed_native_admission': False, 'reader_reopened_native_database': False,
        'host_and_source_provenance_checked_by_reader': False,
        'native_activation_observed_clock_api': True,
        'native_growth_activation_clock_checked': profile == 'PGH2',
        'strict_parent_timestamp_increase_recomputed': True,
        'monotonicity_is_a_consensus_rule': False,
        'full_python_transcript_and_product_recomputed': True,
        'proof_hardness_or_quantum_attack_profitability_qualified': False,
        'public_network_qualification': False,
        'qualification': 'HOLD_NO_GO',
        'common_prefix_failure_bound': None,
        'chain_growth_failure_bound': None,
        'chain_quality_failure_bound': None,
        'six_confirmations_failure_bound': None,
        'actual_lifetime_failure_bound': None,
        'production_activation': False,
    }


def analyze(raw_dir, expected_sha256):
    hexadecimal(expected_sha256, 32)
    require(not raw_dir.is_symlink() and raw_dir.is_dir(), 'regular retained profile directory required')
    raw = read_bounded(raw_dir / 'monotone-daa.json', 2 * 1024 * 1024)
    require(sha(raw) == expected_sha256, 'exact externally recorded monotone DAA report digest required')
    report = load_report(raw)
    require(type(report) is dict and type(report.get('backend')) is str
            and report['backend'] in PROFILES and raw_dir.name == report['backend'],
            'profile directory name must match the retained native backend')
    directory = raw_dir / 'packets'
    require(not directory.is_symlink() and directory.is_dir(), 'regular retained packet directory required')
    paths = list(directory.iterdir())
    require(len(paths) == PACKET_COUNT, 'complete bounded 114-packet inventory required')
    packets = {}
    for path in paths:
        require(re.fullmatch('[0-9a-f]{64}\\.pnk', path.name) is not None, 'unexpected retained packet filename')
        packets['packets/' + path.name] = read_bounded(path, MAX_PACKET_BYTES)
    result = analyze_report(report, packets)
    result['report_sha256'] = sha(raw)
    result['packet_identities'] = {
        name: {'sha256': sha(data), 'bytes': len(data)} for name, data in sorted(packets.items())}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-report-sha256', required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.raw_dir, args.expected_report_sha256)
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print(json.dumps({'schema': READER_SCHEMA, 'result': 'FAIL', 'error': str(error)}))
        return 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
