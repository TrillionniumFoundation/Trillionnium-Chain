#!/usr/bin/env python3
"""Replay the exact seven-packet native branch-work-schedule research export.

Raw packet framing/challenges and complete scalar W1 replay reuse the #794
reader. The new target/anchor/time/work checks are reconstructed separately.
Native admission, cold reopening and account-state execution remain external
runner observations. An externally supplied report digest pins bytes, not
source/host provenance or authority to install the research policy.
"""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'formal' / 'pon-nakamoto-v1'))
import pon_joint_daa_reader as retained
from quantum_daa_model import asert_target

require = retained.require
integer = retained.integer
hexadecimal = retained.hexadecimal
sha = retained.sha
wire = retained.wire
work_oracle = retained.work_oracle
load_report = retained.load_report
fields = retained.fields

SCHEMA = 'pon-native-branch-work-schedule-v1'
PROFILE_SCHEMA = 'pon-branch-work-schedule-research-v1'
GENESIS_TIME = 1_750_000_000
POW_LIMIT = (1 << 255) - 1
MAX_REPORT_BYTES = 131_072
COHORT = (
    ('first', None, 1, 10), ('fast', 'first', 2, 11),
    ('high', 'first', 2, 100), ('other_anchor', None, 1, 20),
    ('fresh_adjusted', 'fast', 3, 12), ('backwards', 'high', 3, 11),
    ('equal', 'high', 3, 100),
)
QUALIFICATIONS = set('''native_new_profile_installed default_consensus_rules_changed
production_activation minimum_cost_qualified quantum_cost_qualified
joint_consensus_security_proven full_execution_identity_verified'''.split())
REPORT_FIELDS = set('''schema backend header_profile settings_scope task_profile
profile records native_observations'''.split()) | QUALIFICATIONS
PROFILE_FIELDS = set('''schema id network parameters genesis genesis_timestamp
initial_target pow_limit legacy_interval spacing_seconds future_skew_seconds
median_window max_research_height activation_height half_life_seconds'''.split())
ROW_FIELDS = set('''label packet_file packet_bytes packet_sha256 id header_hex
challenge proof_bytes proof_sha256 trace parent height timestamp actual_target
required_target parent_branch anchor median_time_past parent_cumulative_work_hex
block_work_hex candidate_cumulative_work_hex expected_research_verdict
observed_research_verdict complete_native_work_verification native_admission_observed
cold_storage_observation'''.split())
OBSERVATION_FIELDS = set('''original_fresh_refusal wrong_product_refusal
cancellation_refusal backwards_research_refusal cross_fork_anchor_refusal
cold_nonmonotone_refusal cold_fast_context_equal cold_c0_context_equal
c0_profile_id c0_parent c0_required_target c0_parent_cumulative_work_hex'''.split())
ANCHOR_FIELDS = {'profile', 'block', 'height', 'target', 'parent_time'}


def profile_id(profile, header_profile, fixed=False):
    """Rebuild the native profile encoding, never use its advertised digest."""
    parts = [hexadecimal(profile[name], 32) for name in
             ('network', 'parameters', 'genesis', 'initial_target', 'pow_limit')]
    parts.extend(wire.u64(profile[name]) for name in
                 ('genesis_timestamp', 'legacy_interval', 'spacing_seconds',
                  'future_skew_seconds', 'max_research_height'))
    parts.append(bytes([1 if header_profile == 'PNH1' else 2, 0 if fixed else 1]))
    if not fixed:
        parts.extend(wire.u64(profile[name]) for name in
                     ('activation_height', 'half_life_seconds'))
    return wire.H(PROFILE_SCHEMA, b''.join(parts))


def checked_work(value):
    require(type(value) is int and 0 <= value < (1 << 512),
            'checked 512-bit cumulative work overflow')
    return value


def work_hex(value):
    return checked_work(value).to_bytes(64, 'big').hex()


def check_profile(report):
    backend = report['backend']
    require(type(backend) is str and backend in retained.PROFILES, 'unsupported backend')
    header_profile = retained.PROFILES[backend]
    require(report['header_profile'] == header_profile, 'backend/header profile mismatch')
    require(report['settings_scope'] == 'actual-schedule-inputs-and-task-profile-only',
            'settings scope must remain explicitly partial')
    require(type(report['task_profile']) is str and 1 <= len(report['task_profile']) <= 128,
            'bounded observed task-profile name required')
    profile = report['profile']
    fields(profile, PROFILE_FIELDS, 'research profile')
    require(profile['schema'] == PROFILE_SCHEMA, 'research profile schema')
    exact = {'genesis_timestamp': GENESIS_TIME, 'legacy_interval': 16,
             'spacing_seconds': 10, 'future_skew_seconds': 120, 'median_window': 11,
             'max_research_height': 4096, 'activation_height': 1, 'half_life_seconds': 160}
    for name, expected in exact.items():
        require(integer(profile[name], name) == expected, 'fixed experiment parameter: ' + name)
    for name in ('network', 'parameters', 'genesis'):
        hexadecimal(profile[name], 32)
    for name in ('initial_target', 'pow_limit'):
        require(int.from_bytes(hexadecimal(profile[name], 32), 'big') == POW_LIMIT,
                'fixed experiment initial target and limit')
    identity = profile_id(profile, header_profile)
    require(hexadecimal(profile['id'], 32) == identity, 'profile digest mismatch')
    return profile, header_profile, identity


def analyze_report(report, packet_bytes):
    fields(report, REPORT_FIELDS, 'research report')
    require(report['schema'] == SCHEMA, 'research report schema')
    for name in QUALIFICATIONS:
        require(report[name] is False, 'unsupported qualification: ' + name)
    profile, header_profile, identity = check_profile(report)
    genesis = hexadecimal(profile['genesis'], 32)
    network = hexadecimal(profile['network'], 32)
    parameters = hexadecimal(profile['parameters'], 32)
    names = {'packets/' + label + '.pnk' for label, _, _, _ in COHORT}
    require(type(packet_bytes) is dict and set(packet_bytes) == names,
            'exact seven-packet inventory required')
    records = report['records']
    require(type(records) is list and len(records) == len(COHORT),
            'exact seven-record trajectory required')
    decoded, lineage, totals, seen, summaries = {}, {}, {}, {genesis}, []
    genesis_header = {'id': genesis, 'height': 0, 'timestamp': GENESIS_TIME,
                      'target': POW_LIMIT.to_bytes(32, 'big')}
    for row, (label, parent_label, height, offset) in zip(records, COHORT):
        fields(row, ROW_FIELDS, 'native packet observation')
        require(row['label'] == label, 'fixed seven-packet order')
        filename = 'packets/' + label + '.pnk'
        require(row['packet_file'] == filename, 'fixed packet filename')
        raw = packet_bytes[filename]
        require(type(raw) is bytes and integer(row['packet_bytes'], 'packet bytes') == len(raw)
                and hexadecimal(row['packet_sha256'], 32).hex() == sha(raw),
                'packet bytes changed after native observation')
        packet = retained.decode_packet(header_profile, raw)
        header, proof, identifier = packet['header'], packet['proof'], packet['id']
        require(identifier not in seen, 'duplicate block identity')
        seen.add(identifier)
        require(hexadecimal(row['id'], 32) == identifier, 'raw block identity mismatch')
        require(hexadecimal(row['header_hex'], len(packet['header_raw'])) == packet['header_raw'],
                'raw header mismatch')
        require(hexadecimal(row['challenge'], 32) == packet['challenge'], 'actual challenge mismatch')
        require(integer(row['proof_bytes'], 'proof bytes') == work_oracle.PROOF_BYTES
                and hexadecimal(row['proof_sha256'], 32).hex() == sha(proof)
                and hexadecimal(row['trace'], 32) == proof[-32:], 'raw proof observation mismatch')
        require(header['network'] == network and header['parameters'] == parameters,
                'expected namespace mismatch')
        require(header['transactions'] == wire.sequence_root('transactions', []),
                'empty transaction root mismatch')
        for name in ('height', 'timestamp'):
            require(integer(row[name], name) == header[name], 'actual header ' + name)
        require(header['height'] == height and header['timestamp'] == GENESIS_TIME + offset,
                'fixed raw timestamp/height trajectory')
        parent_packet = decoded.get(parent_label)
        parent = genesis if parent_packet is None else parent_packet['id']
        require(header['parent'] == parent and hexadecimal(row['parent'], 32) == parent,
                'actual parent fork mismatch')
        chain = ([genesis_header] if parent_label is None else
                 [{'id': parent_packet['id'], **parent_packet['header']}] + lineage[parent_label])
        lineage[label] = chain
        require(row['parent_branch'] == [item['id'].hex() for item in chain if item['height']],
                'complete parent-first branch mismatch')
        recent = [item['timestamp'] for item in chain[:11]]
        median = sorted(recent)[len(recent) // 2]
        require(integer(row['median_time_past'], 'median') == median, 'median mismatch')
        anchor = next((item for item in chain if item['height'] == 1), None)
        if anchor is None:
            require(row['anchor'] is None, 'preactivation branch cannot advertise an anchor')
            expected_target = POW_LIMIT
        else:
            expected_anchor = {'profile': identity.hex(), 'block': anchor['id'].hex(),
                               'height': 1, 'target': anchor['target'].hex(),
                               'parent_time': GENESIS_TIME}
            fields(row['anchor'], ANCHOR_FIELDS, 'branch anchor')
            integer(row['anchor']['height'], 'anchor height')
            integer(row['anchor']['parent_time'], 'anchor parent time')
            require(row['anchor'] == expected_anchor, 'actual branch anchor mismatch')
            expected_target = asert_target(int.from_bytes(anchor['target'], 'big'),
                                           chain[0]['timestamp'] - GENESIS_TIME,
                                           height - 1, 10, 160, POW_LIMIT)
        target = int.from_bytes(header['target'], 'big')
        require(target == expected_target, 'actual target differs from parent-anchored ASERT')
        for name in ('actual_target', 'required_target'):
            require(hexadecimal(row[name], 32) == header['target'], 'reported target mismatch')
        weight = (1 << 256) // (expected_target + 1)
        parent_work = 0 if parent_label is None else totals[parent_label]
        require(row['block_work_hex'] == work_hex(weight), 'exact expected-target block work')
        require(row['parent_cumulative_work_hex'] == work_hex(parent_work),
                'exact parent cumulative work')
        if height > 1 and header['timestamp'] < chain[0]['timestamp']:
            verdict = 'SCHEDULE_TIME_NONDECREASING'
        elif header['timestamp'] <= median:
            verdict = 'SCHEDULE_TIME_MTP'
        else:
            verdict = 'PASS'
        expected_verdict = 'SCHEDULE_TIME_NONDECREASING' if label == 'backwards' else 'PASS'
        require(verdict == expected_verdict, 'raw time-rule outcome changed')
        require(header['timestamp'] > median, 'backwards control must independently pass MTP')
        require(row['expected_research_verdict'] == verdict
                and row['observed_research_verdict'] == verdict, 'research verdict mismatch')
        total = checked_work(parent_work + weight)
        expected_credit = work_hex(total) if verdict == 'PASS' else None
        require(row['candidate_cumulative_work_hex'] == expected_credit,
                'rejected candidate cannot acquire research work credit')
        require(row['complete_native_work_verification'] is True,
                'complete native W1 observation missing')
        native_verdict = 'TARGET' if label == 'fresh_adjusted' else 'admitted'
        require(row['native_admission_observed'] == native_verdict,
                'original-policy admission observation changed')
        expected_storage = 'not-retained' if label == 'fresh_adjusted' else 'retained-byte-identical'
        require(row['cold_storage_observation'] == expected_storage,
                'cold packet observation changed')
        if label == 'fresh_adjusted':
            require(target < POW_LIMIT, 'isolation control must change the original required target')
        else:
            require(target == POW_LIMIT, 'legacy-admitted control target changed')
        decoded[label], totals[label] = packet, total
        summaries.append({'label': label, 'id': identifier.hex(), 'target': header['target'].hex(),
                          'research_verdict': verdict, 'original_native_observation': native_verdict})

    observations = report['native_observations']
    fields(observations, OBSERVATION_FIELDS, 'native controls')
    exact_errors = {'original_fresh_refusal': 'TARGET', 'wrong_product_refusal': 'WORK:Product',
                    'cancellation_refusal': 'SCHEDULE_TEST_CANCELLED',
                    'backwards_research_refusal': 'SCHEDULE_TIME_NONDECREASING',
                    'cross_fork_anchor_refusal': 'SCHEDULE_ANCHOR_MISMATCH',
                    'cold_nonmonotone_refusal': 'SCHEDULE_TIME_NONDECREASING'}
    for name, expected in exact_errors.items():
        require(observations[name] == expected, 'native control observation changed: ' + name)
    for name in ('cold_fast_context_equal', 'cold_c0_context_equal'):
        require(observations[name] is True, 'cold context observation changed')
    require(observations['c0_profile_id'] == profile_id(profile, header_profile, fixed=True).hex(),
            'C0 profile digest mismatch')
    require(observations['c0_parent'] == decoded['fast']['id'].hex(), 'C0 parent branch mismatch')
    require(observations['c0_required_target'] == POW_LIMIT.to_bytes(32, 'big').hex(),
            'C0 target must stay fixed')
    require(observations['c0_parent_cumulative_work_hex'] == work_hex(4),
            'C0 original work units changed')
    require(decoded['first']['id'] != decoded['other_anchor']['id'],
            'cross-fork anchor control must use a distinct activation ancestor')
    # No cheap-filter-only success path. Replay every retained relation at the
    # actual header target, including the timestamp-rejected complete proof.
    for label, packet in decoded.items():
        try:
            work_oracle.verify(packet['challenge'], packet['header']['work_task'],
                               packet['header']['target'], packet['proof'])
        except ValueError as error:
            raise ValueError('full W1 ' + label + ': ' + str(error)) from error
    return {
        'schema': 'pon-native-branch-work-schedule-reader-v1',
        'record_and_oracle_consistency': 'PASS', 'backend': report['backend'],
        'profile_id': identity.hex(), 'unique_full_python_verified_proofs': 7,
        'independent_research_time_refusals': 1, 'research_schedule_passes': 6,
        'unique_legacy_native_admitted_packets_observed': 6,
        'full_python_transcript_and_product_recomputed': True,
        'actual_target_correct_for_time_rejected_proof': True,
        'fresh_adjusted_target_native_refusal_is_only_policy_isolation': True,
        'cold_context_equality_is_external_native_observation': True,
        'growth_witness_hashes_recomputed': 7 if header_profile == 'PGH2' else 0,
        'reader_verified_growth_account_proofs': False,
        'reader_replayed_state_execution_or_task_eligibility': False,
        'reader_performed_native_admission': False, 'reader_reopened_native_database': False,
        'host_and_source_provenance_checked_by_reader': False,
        **{name: False for name in QUALIFICATIONS}, 'records': summaries,
    }


def read_bounded(path, maximum):
    require(not path.is_symlink() and path.is_file(), 'regular retained file required')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'retained file exceeds byte limit')
    return raw


def analyze(raw_dir, expected_sha256):
    raw_dir = Path(raw_dir)
    require(not raw_dir.is_symlink() and raw_dir.is_dir(), 'regular evidence directory required')
    require(raw_dir.name in retained.PROFILES, 'canonical backend directory required')
    require({path.name for path in raw_dir.iterdir()} == {'report.json', 'report.sha256', 'packets'},
            'exact evidence directory inventory required')
    raw = read_bounded(raw_dir / 'report.json', MAX_REPORT_BYTES)
    expected = hexadecimal(expected_sha256, 32).hex()
    require(sha(raw) == expected, 'externally recorded research report digest mismatch')
    require(read_bounded(raw_dir / 'report.sha256', 65) == (expected + '\n').encode('ascii'),
            'retained report digest mismatch')
    report = load_report(raw)
    require(type(report) is dict and report.get('backend') == raw_dir.name,
            'export directory does not match its observed backend')
    directory = raw_dir / 'packets'
    require(not directory.is_symlink() and directory.is_dir(), 'regular packet directory required')
    expected_names = {label + '.pnk' for label, _, _, _ in COHORT}
    require({path.name for path in directory.iterdir()} == expected_names,
            'exact seven-packet inventory required')
    packets = {'packets/' + name: read_bounded(directory / name, retained.MAX_PACKET_BYTES)
               for name in sorted(expected_names)}
    result = analyze_report(report, packets)
    result['externally_pinned_report_sha256'] = expected
    result['packet_identities'] = {name: {'sha256': sha(data), 'bytes': len(data)}
                                   for name, data in sorted(packets.items())}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--report-sha256', required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.raw_dir, args.report_sha256)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'record_and_oracle_consistency': 'FAIL', 'error': str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
