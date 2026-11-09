#!/usr/bin/env python3
"""Independently replay retained PNH1/PGH2 joint-consensus DAA evidence.

Only the exact finite native experiment is accepted. This reader recomputes
header domains, complete PNW1 transcripts/products, branch targets, MTP/future
rules and linear cumulative work. PGH2 witness bytes are bounded and hashed;
account-proof validity, task eligibility, M06 execution, native SQL admission
and cold-reopen behavior remain observations of the external native runner.
An externally recorded report digest pins bytes, not source or host provenance.
The export directory must retain its canonical backend name so separate CI
profile lanes cannot both certify a copied report from the same native owner.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import pon_daa_schedule_reader as retained

require = retained.require
integer = retained.integer
hexadecimal = retained.hexadecimal
sha = retained.sha
load_report = retained.load_report
wire = retained.wire
reference = retained.reference
work_oracle = retained.work_oracle

SCHEMA = 'pon-native-joint-daa-v1'
READER_SCHEMA = 'pon-native-joint-daa-reader-v1'
GENESIS_TIME = 1_750_000_000
PROFILES = {'pnh1-authenticated': 'PNH1', 'pgh2-growth': 'PGH2'}
ALTERED = 'repeated-negative-endpoints'
COHORT = ([('common', height) for height in range(1, 16)]
          + [(name, height) for height in range(16, 65) for name in ('ordinary', ALTERED)]
          + [('ordinary', 65)])
PACKET_COUNT = 114
MAX_PACKET_BYTES = 1_048_576
MAX_WITNESS_BYTES = 786_432
REPORT_FIELDS = set('''schema backend header_profile work_profile network parameters genesis
genesis_timestamp genesis_chainwork_hex initial_target pow_limit interval spacing_seconds
median_window future_skew_seconds desired_span_seconds clamped_span_lower_seconds
clamped_span_upper_seconds records retargets activations binding_rejections ordinary_tip
altered_tip ordinary_chainwork_hex altered_chainwork_hex after_cold_reopen
shorter_higher_work_branch_selected activation_observed_clock_api
growth_activation_clock_checked default_consensus_rules_changed logical_validation_clock_schedule
wall_clock_cadence_measured attacker_work_fraction_measured quantum_attack_profitability_measured
public_network_qualification'''.split())
ROW_FIELDS = set('''schedule height id parent timestamp observed_now
ancestor_timestamps_parent_first median_time_past target required_work_hex header_hex
challenge nonce attempts proof_bytes proof_sha256 trace packet_bytes packet_sha256
packet_file complete_native_work_verification admission'''.split())
RETARGET_FIELDS = set('''height first_timestamp last_timestamp signed_span_seconds
saturating_span_seconds effective_span_seconds parent_target next_target'''.split())
BINDING_FIELDS = set('''changed_field unchanged_proof_sha256 changed_challenge work_error
full_transcript_error_with_permissive_filter diagnostic_filter_is_not_consensus'''.split())
COMMON_HEAD_FIELDS = set('''network parameters genesis tip height chainwork_hex state_root
generation production_activation'''.split())
PNH_HEAD_FIELDS = COMMON_HEAD_FIELDS | set('''state_keys stored_blocks events
authenticated_sessions authenticated_pending authenticated_audit_rows
authenticated_outbox_sessions authenticated_outbox_pending'''.split())
PGH_HEAD_FIELDS = COMMON_HEAD_FIELDS | set('''schema packet_profile state_profile
local_target_only confirmation_authority finality_authority execution_authority'''.split())


def fields(value, expected, name):
    require(type(value) is dict and set(value) == expected,
            name + ': exact fields required; missing or additional scope is not evidence')


def header_challenge(profile, header):
    domain = 'challenge' if profile == 'PNH1' else 'permanent-account-growth-challenge-v2'
    return wire.H(domain, header)


def block_id(profile, header, trace):
    domain = 'block' if profile == 'PNH1' else 'permanent-account-growth-block-v2'
    return wire.H(domain, header, trace)


def check_witness_envelope(witness):
    """Bound AAM1 framing only; do not claim sparse-tree or execution validity."""
    require(44 <= len(witness) <= MAX_WITNESS_BYTES and witness[:4] == b'AAM1',
            'bounded AAM1 witness framing required')
    accounts = int.from_bytes(witness[36:40], 'little')
    frontier = int.from_bytes(witness[40:44], 'little')
    require(1 <= accounts <= 1024 and frontier <= 65_536,
            'AAM1 envelope dimensions exceed the native growth packet bounds')
    require(44 + 33 * accounts + 66 * frontier <= len(witness),
            'truncated AAM1 envelope dimensions')
    position = 44
    for _ in range(accounts):
        require(position + 33 <= len(witness), 'truncated AAM1 account envelope')
        present = witness[position + 32]
        require(present in (0, 1), 'noncanonical AAM1 account presence')
        position += 33 + 16 * present
    require(position + 66 * frontier == len(witness), 'AAM1 envelope has missing or trailing bytes')


def decode_packet(profile, raw):
    require(profile in ('PNH1', 'PGH2'), 'unsupported header profile')
    require(type(raw) is bytes and len(raw) <= MAX_PACKET_BYTES, 'bounded retained packet bytes required')
    if profile == 'PNH1':
        require(len(raw) == 318 + 2 + work_oracle.PROOF_BYTES,
                'complete empty-transaction PNH1 packet length required')
        header_raw, ledger_raw, proof_offset, witness = raw[:318], raw[:318], 320, b''
        require(raw[318:320] == b'\x00\x00', 'joint DAA schedule requires zero transactions')
    else:
        require(len(raw) >= 4 + 354 + 2 + 4 + 44 + work_oracle.PROOF_BYTES
                and raw[:4] == b'PNP2' and raw[4:8] == b'PGH2',
                'complete PNP2/PGH2 packet framing required')
        header_raw, ledger_raw = raw[4:358], raw[8:326]
        require(raw[358:360] == b'\x00\x00', 'joint DAA schedule requires zero transactions')
        witness_length = int.from_bytes(raw[360:364], 'little')
        require(44 <= witness_length <= MAX_WITNESS_BYTES
                and len(raw) == 364 + witness_length + work_oracle.PROOF_BYTES,
                'exact bounded growth witness/proof lengths required')
        proof_offset = 364 + witness_length
        witness = raw[364:proof_offset]
        check_witness_envelope(witness)
        require(wire.H('native-growth-account-witness-v2', witness) == header_raw[-32:],
                'PGH2 witness commitment differs from retained AAM1 bytes')
    header = wire.header_decode(ledger_raw)
    require(wire.header_encode(header) == ledger_raw, 'noncanonical ledger header')
    proof = raw[proof_offset:]
    return {'header': header, 'header_raw': header_raw, 'ledger_raw': ledger_raw,
            'proof': proof, 'proof_offset': proof_offset, 'witness': witness,
            'challenge': header_challenge(profile, header_raw),
            'id': block_id(profile, header_raw, proof[-32:])}


def check_head(head, profile, report, admitted, expected_tip, generation, events):
    fields(head, PNH_HEAD_FIELDS if profile == 'PNH1' else PGH_HEAD_FIELDS, 'native head observation')
    for key in ('network', 'parameters', 'genesis'):
        require(hexadecimal(head[key], 32) == hexadecimal(report[key], 32), 'native head context changed')
    require(hexadecimal(head['tip'], 32) == expected_tip, 'activation does not select its actual branch')
    selected = admitted[expected_tip]
    require(integer(head['height'], 'active height') == selected['height']
            and integer(head['generation'], 'active generation') == generation,
            'native activation height/generation mismatch')
    require(int.from_bytes(hexadecimal(head['chainwork_hex'], 64), 'big') == selected['work'],
            'native activation chainwork differs from linear branch work')
    require(hexadecimal(head['state_root'], 32) == selected['state'],
            'native active root differs from its selected header')
    require(head['production_activation'] is False, 'native observation cannot grant production activation')
    if profile == 'PNH1':
        require(integer(head['stored_blocks'], 'stored blocks') == PACKET_COUNT + 1,
                'native inventory must contain genesis and every accepted packet')
        require(integer(head['events'], 'native reorg events') == events,
                'native reorg event count differs from actual undo/apply paths')
        integer(head['state_keys'], 'native state key count', 1)
        for key in PNH_HEAD_FIELDS - COMMON_HEAD_FIELDS - {'state_keys', 'stored_blocks', 'events'}:
            require(integer(head[key], key) == 0, 'standalone DAA experiment cannot claim authenticated sessions')
    else:
        require(head['schema'] == 'pon-native-growth-head-observation-v1'
                and head['packet_profile'] == 'PNP2'
                and head['state_profile'] == 'permanent-account-growth-native-v2',
                'growth native head profile changed')
        require(head['local_target_only'] is True, 'growth head must retain its local observation scope')
        for key in ('confirmation_authority', 'finality_authority', 'execution_authority'):
            require(head[key] is False, 'growth head cannot grant authority: ' + key)


def check_bindings(probes, profile, final_packet):
    names = ['parent', 'target', 'timestamp', 'nonce']
    if profile == 'PGH2':
        names.append('growth_witness')
    require(type(probes) is list and len(probes) == len(names), 'complete changed-header binding probes required')
    prepared = []
    for name, probe in zip(names, probes):
        fields(probe, BINDING_FIELDS, 'binding probe')
        require(probe['changed_field'] == name, 'binding probe order or field changed')
        require(probe['diagnostic_filter_is_not_consensus'] is True
                and probe['full_transcript_error_with_permissive_filter'] == 'Transcript',
                'full transcript diagnostic must retain its non-consensus permissive filter scope')
        header = copy.deepcopy(final_packet['header'])
        if name == 'parent':
            header[name] = bytes([header[name][0] ^ 1]) + header[name][1:]
        elif name == 'target':
            header[name] = header[name][:-1] + bytes([header[name][-1] ^ 1])
        elif name == 'timestamp':
            header[name] += 1
        elif name == 'nonce':
            header[name] ^= 1
        header_raw = wire.header_encode(header)
        if profile == 'PGH2':
            witness_digest = final_packet['header_raw'][-32:]
            if name == 'growth_witness':
                witness_digest = bytes([witness_digest[0] ^ 1]) + witness_digest[1:]
            header_raw = b'PGH2' + header_raw + witness_digest
        challenge = header_challenge(profile, header_raw)
        require(challenge != final_packet['challenge'], 'changed header did not change the challenge')
        require(hexadecimal(probe['changed_challenge'], 32) == challenge,
                'binding probe challenge differs from exact declared header mutation')
        require(hexadecimal(probe['unchanged_proof_sha256'], 32).hex() == sha(final_packet['proof']),
                'binding probe must reuse the unchanged final packet proof')
        require(probe['work_error'] in ('Target', 'Transcript'), 'unsupported changed-header rejection claim')
        prepared.append((name, probe, challenge, header))
    # Cheap Target refusal is independently checked, but cannot substitute for
    # the second complete transcript replay with only the verifier filter set to ff.
    for name, probe, challenge, header in prepared:
        args = (challenge, header['work_task'], header['target'], final_packet['proof'])
        try:
            work_oracle.verify(*args)
        except ValueError as error:
            actual = {'TARGET': 'Target', 'TRANSCRIPT': 'Transcript'}.get(str(error))
            require(actual == probe['work_error'], 'binding probe rejection mismatch: ' + name)
        else:
            raise ValueError('unchanged proof unexpectedly passed changed header: ' + name)
        try:
            work_oracle.verify(challenge, header['work_task'], b'\xff' * 32, final_packet['proof'])
        except ValueError as error:
            require(str(error) == 'TRANSCRIPT', 'binding permissive-filter replay must fail full transcript: ' + name)
        else:
            raise ValueError('binding permissive-filter replay unexpectedly passed: ' + name)
    return len(names)


def analyze_report(report, packet_bytes):
    fields(report, REPORT_FIELDS, 'joint DAA report')
    require(report['schema'] == SCHEMA, 'unsupported native joint DAA report')
    require(report['backend'] in PROFILES and report['header_profile'] == PROFILES[report['backend']]
            and report['work_profile'] == 'PNW1', 'native backend/header/work profile mismatch')
    profile = report['header_profile']
    exact = {'genesis_timestamp': GENESIS_TIME, 'interval': 16, 'spacing_seconds': 10,
             'median_window': 11, 'future_skew_seconds': 120, 'desired_span_seconds': 150,
             'clamped_span_lower_seconds': 38, 'clamped_span_upper_seconds': 600}
    for key, value in exact.items():
        require(integer(report[key], key) == value, 'fixed joint DAA experiment changed: ' + key)
    for key in ('growth_activation_clock_checked', 'default_consensus_rules_changed',
                'wall_clock_cadence_measured', 'attacker_work_fraction_measured',
                'quantum_attack_profitability_measured', 'public_network_qualification'):
        require(report[key] is False, 'unsupported qualification or activation-clock claim: ' + key)
    for key in ('shorter_higher_work_branch_selected', 'logical_validation_clock_schedule'):
        require(report[key] is True, 'required finite native observation scope: ' + key)
    require(report['activation_observed_clock_api'] is (profile == 'PNH1'),
            'native activation observed-clock API must match the actual owner profile')
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
                require(last < first, 'three strict negative endpoint spans required')
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
        timestamp = GENESIS_TIME + height * 10 if schedule != ALTERED or height % 16 == 0 else median + 1
        require(header['timestamp'] == timestamp and now == GENESIS_TIME + height * 10,
                'fixed logical timestamp/clock schedule changed')
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
                'retarget observation differs from actual negative endpoint lineage')
    require([item['signed_span_seconds'] for item in computed_retargets] == ['-42', '-199', '-356'],
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
        'native_activation_observed_clock_api': profile == 'PNH1',
        'native_growth_activation_clock_checked': False,
        'full_python_transcript_and_product_recomputed': True,
        'proof_hardness_or_quantum_attack_profitability_qualified': False,
        'public_network_qualification': False,
    }


def read_bounded(path, maximum):
    require(not path.is_symlink() and path.is_file(), 'retained evidence must be a regular nonsymlink file')
    return retained.read_bounded(path, maximum)


def analyze(raw_dir, expected_sha256):
    hexadecimal(expected_sha256, 32)
    require(not raw_dir.is_symlink() and raw_dir.is_dir(), 'regular retained profile directory required')
    raw = read_bounded(raw_dir / 'joint-daa.json', 2 * 1024 * 1024)
    require(sha(raw) == expected_sha256, 'exact externally recorded joint DAA report digest required')
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
