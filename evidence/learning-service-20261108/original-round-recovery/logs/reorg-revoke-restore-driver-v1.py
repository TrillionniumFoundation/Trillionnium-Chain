import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/home/qq/chain-real-iteration-20261108-8b4f0eedf006')
ROUND = ROOT / 'artifacts/development-iteration-v1/native-service'
OUT = ROOT / 'faults/reorg-revoke-restore-v1'
ORIGINAL = ROOT / 'bin/learning_service_round-fc406bad'
PROBE = ROOT / 'bin/learning_service_recovery_probe-414dd728'
IDENTITY = '05d2acaf505b3e7da1cdf2e9daff8881608dcfe621fcb3dc506cba344db72ce9'
INTENT = '5076ac05ac74835a8ab9a567a3e8833759a0eac53a39587064e711bb2ed5146c'
OPERATION = 'dev-learning-service-8b4f-v1'
PINS = {
    ORIGINAL: 'fc406badb161bd9847b9aa3b7f5863018baae62b172467e2ae3a44317a76808a',
    PROBE: '414dd7288418b8df225f80b1090c31d42547a63a61592d25055f2a475e1c9a57',
    ROUND / 'identity.json': IDENTITY,
    ROOT / 'artifacts/development-iteration-v1/result.json': '161a3bd2b194b2c8f6df598697cf2828c42df5e1657911bd42ca11e857175616',
    ROOT / 'logs/integrated-cold-query-v1.stdout.log': '8ab71e7204b8a2baeb3fbf2ef58f280e6310a3fce6a01a602c8293c503905e06',
}
IDS = {
    'operation_id': OPERATION,
    'intent_sha256': INTENT,
    'native_operation': 'a42d024b4d1dab9293db261e3fa058f14b808697bd017de1c108e517b8a11b67',
    'task': 'e95486d0d020e0cf8960b19fc66a5b6f547903c604f19474b35b4307e5be0ced',
    'claim': 'de53803fc3c525768f97f57df22d649b32dbd55fc4dfbd19b24ca956b2b51ecc',
    'provider_authority_id': 'f1a0e77bb60b875fed95f09a20d7c09e8ae51722d8ad730819ef0d5fbb30a371',
}


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def persist(path, data):
    raw = json.dumps(data, indent=2, sort_keys=True).encode() + b'\n'
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check(ok, message):
    if not ok:
        raise RuntimeError(message)


def read(path):
    return json.loads(path.read_bytes())


def phase(label, argv):
    before = {'label': label, 'argv': [str(x) for x in argv], 'started_unix_ns': time.time_ns(),
              'same_original_round': str(ROUND), 'automatic_retry_allowed': False}
    persist(OUT / (label + '-intent.json'), before)
    started = time.monotonic_ns()
    stdout = OUT / (label + '.stdout.json')
    stderr = OUT / (label + '.stderr.log')
    with stdout.open('xb') as o, stderr.open('xb') as e:
        completed = subprocess.run(before['argv'], stdin=subprocess.DEVNULL, stdout=o, stderr=e,
                                   cwd=ROOT, check=False)
        o.flush()
        e.flush()
        os.fsync(o.fileno())
        os.fsync(e.fileno())
    receipt = {**before, 'exit_code': completed.returncode, 'wall_ns': time.monotonic_ns() - started,
               'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
               'stdout_bytes': stdout.stat().st_size, 'stderr_bytes': stderr.stat().st_size,
               'finished_unix_ns': time.time_ns()}
    persist(OUT / (label + '-process.json'), receipt)
    check(completed.returncode == 0, label + ' nonzero original exit; query only, do not replay')
    result = read(stdout)
    print(json.dumps({'phase': label, 'exit_code': completed.returncode,
                      'probe_state': result.get('probe_state'), 'status': result.get('status'),
                      'current_branch_base_fee': result.get('current_branch_base_fee'),
                      'historically_observed_base_fee': result.get('historically_observed_base_fee'),
                      'locally_revoked': result.get('locally_revoked'),
                      'native': result.get('native'),
                      'maintenance_dispatch_performed': result.get('maintenance_dispatch_performed'),
                      'stdout_sha256': receipt['stdout_sha256']}), flush=True)
    return result


def probe(label, command):
    return phase(label, [PROBE, command, ROUND, IDENTITY, INTENT, OPERATION])


def native(label, command):
    return phase(label, [ORIGINAL, command, ROUND])


def bound(value, fee, revoked, reference):
    for key, expected in IDS.items():
        check(value[key] == expected, 'original binding changed: ' + key)
    check(value['current_branch_base_fee'] == fee, 'unexpected current fee')
    check(value['historically_observed_base_fee'] == 2000, 'historical fee changed')
    check(value['locally_revoked'] is revoked, 'revocation mismatch')
    check(value['m12'] == reference['m12'], 'M12 journal changed')
    check(value['model_state_unchanged'] is True, 'model state changed')
    if 'resource_reservation' in value:
        check(value['resource_reservation'] == reference['resource_reservation'], 'resource state changed')
    if 'service_dispatch_allowed' in value:
        check(value['service_dispatch_allowed'] is False and value['model_execution_performed'] is False,
              'unexpected service or model dispatch')
        check(value['m12_unchanged'] is True and value['provider_receipt_reissued'] is False,
              'unexpected journal or provider dispatch')


def probe_shape(value, state, height, membership, dispatched):
    check(value['probe_state'] == state, 'unexpected probe phase')
    check(value['native']['height'] == height, 'unexpected native height')
    check(value['original_payment_packet']['active_chain_member'] is membership, 'payment membership mismatch')
    check(value['maintenance_dispatch_performed'] is dispatched, 'maintenance dispatch mismatch')


def compact(value):
    keys = ['probe_state', 'native', 'current_branch_base_fee', 'historically_observed_base_fee',
            'locally_revoked', 'original_payment_packet', 'maintenance_economics', 'expected_absent_source_error',
            'original_paid_activation', 'original_paid_tip', 'original_paid_chainwork_hex', 'probe_intent_sha256',
            'maintenance_dispatch_performed', 'source_pins']
    return {key: value[key] for key in keys if key in value}


def main():
    for path, expected in PINS.items():
        check(not path.is_symlink() and sha(path) == expected, 'preflight SHA mismatch: ' + str(path))
    restored = read(ROOT / 'faults/provider-directory-loss-v1/result.json')
    check((ROOT / 'artifacts/development-iteration-v1/trial/candidate').is_dir(), 'provider directory not restored')
    check(not (ROUND / 'recovery-probe-v1').exists(), 'probe already attempted: query original only')
    reference = read(ROOT / 'faults/provider-directory-loss-v1/after-restored.stdout.json')
    bound(reference, 2000, False, reference)
    OUT.mkdir(mode=0o700)
    persist(OUT / 'driver-intent.json', {'schema': 'same-original-round-reorg-revoke-restore-driver-v1',
        'scope': 'local-development-same-native-owner', 'original_round': str(ROUND), 'identifiers': IDS,
        'frozen_pins': {str(k): v for k, v in PINS.items()}, 'retry_allowed': False,
        'sequence': ['probe-query', 'probe-reorg', 'original-query', 'original-revoke', 'probe-restore',
                     'probe-cold-query', 'original-cold-query', 'probe-final-query'],
        'new_service_payment_allowed': False, 'new_model_execution_allowed': False,
        'backup_authority_opened': False, 'ordinary_maintenance_subsidy_separate': True,
        'provider_fault_result_sha256': sha(ROOT / 'faults/provider-directory-loss-v1/result.json'),
        'started_unix_ns': time.time_ns()})
    baseline = probe('00-baseline-probe-query', 'query')
    bound(baseline, 2000, False, reference)
    probe_shape(baseline, 'NOT_STARTED', 3, True, False)
    reorg = probe('01-reorg', 'reorg')
    bound(reorg, 0, False, reference)
    probe_shape(reorg, 'REORG_RECORDED_QUERY_ONLY', 4, False, True)
    check(int(reorg['native']['chainwork_hex'], 16) > int(baseline['native']['chainwork_hex'], 16),
          'reorg did not select heavier chain')
    check(reorg['original_payment_packet']['block'] == baseline['original_payment_packet']['block'],
          'original payment block changed')
    check(reorg['expected_absent_source_error'] == 'TASK_OPERATION_CURRENT_SOURCE_ABSENT_V3',
          'orphaned source unexpectedly present')
    orphaned = native('02-orphaned-original-query', 'query')
    bound(orphaned, 0, False, reference)
    check(orphaned['current_native_observation'] is None, 'original query still observes current payment')
    revoked = native('03-revoke-while-orphaned', 'revoke')
    bound(revoked, 0, True, reference)
    restore = probe('04-restore-original-paid-branch', 'restore')
    bound(restore, 2000, True, reference)
    probe_shape(restore, 'RESTORE_RECORDED_QUERY_ONLY', 5, True, True)
    check(int(restore['native']['chainwork_hex'], 16) > int(reorg['native']['chainwork_hex'], 16),
          'restore did not select heavier original paid branch')
    check(restore['original_payment_packet']['block'] == baseline['original_payment_packet']['block'],
          'restored payment block differs')
    cold_probe = probe('05-restored-probe-cold-query', 'query')
    bound(cold_probe, 2000, True, reference)
    probe_shape(cold_probe, 'RESTORE_RECORDED_QUERY_ONLY', 5, True, False)
    check(cold_probe['native'] == restore['native'], 'cold probe query changed native state')
    cold_original = native('06-restored-original-cold-query', 'query')
    bound(cold_original, 2000, True, reference)
    final_probe = probe('07-final-probe-query', 'query')
    bound(final_probe, 2000, True, reference)
    probe_shape(final_probe, 'RESTORE_RECORDED_QUERY_ONLY', 5, True, False)
    check(final_probe['native'] == restore['native'], 'original cold query changed native state')
    for path, expected in PINS.items():
        check(sha(path) == expected, 'postflight original SHA changed: ' + str(path))
    packet_counts = {phase_name: len(final_probe['phases'][phase_name]['packets']) for phase_name in ('reorg', 'restore')}
    result = {'schema': 'same-original-round-reorg-revoke-restore-result-v1',
        'status': 'RESTORED_ORIGINAL_PAYMENT_REMAINS_LOCALLY_REVOKED', 'identifiers': IDS,
        'scope': 'local-development-same-native-owner', 'original_round': str(ROUND),
        'baseline': compact(baseline), 'orphaned': compact(reorg), 'restored': compact(restore),
        'final_cold': compact(final_probe), 'original_native_final_status': cold_original['status'],
        'reorg_activation': final_probe['phases']['reorg']['original_owner_activation'],
        'restore_activation': final_probe['phases']['restore']['original_owner_activation'],
        'maintenance_packet_counts': packet_counts, 'm12_unchanged': True,
        'resource_reservation': cold_original['resource_reservation'], 'm12': cold_original['m12'],
        'model_state_unchanged': True, 'query_added_native_blocks': False,
        'same_original_payment_block': baseline['original_payment_packet']['block'],
        'new_service_payment': 0, 'new_model_execution': False, 'learning_improvement_bonus': 0,
        'anti_sybil_useful_work_credit': 0, 'ordinary_maintenance_subsidy_separate': True,
        'original_main_and_initial_cold_bytes_unchanged': True,
        'frozen_pins': {str(k): v for k, v in PINS.items()},
        'independent_provider_disappearance_verified': False, 'production_activation': False,
        'finished_unix_ns': time.time_ns()}
    persist(OUT / 'result.json', result)
    print(json.dumps({'status': result['status'], 'result_sha256': sha(OUT / 'result.json'),
                      'current_fee': final_probe['current_branch_base_fee'],
                      'historical_fee': final_probe['historically_observed_base_fee'],
                      'locally_revoked': final_probe['locally_revoked'],
                      'maintenance_packet_counts': packet_counts,
                      'maintenance_economics_before': baseline['maintenance_economics'],
                      'maintenance_economics_after': final_probe['maintenance_economics']}), flush=True)


try:
    main()
except BaseException as error:
    failure = {'status': 'STOPPED_QUERY_ORIGINAL_IDS_ONLY', 'error_type': type(error).__name__,
               'error': str(error), 'recorded_unix_ns': time.time_ns(), 'retry_allowed': False}
    if OUT.is_dir() and not (OUT / 'failure.json').exists():
        persist(OUT / 'failure.json', failure)
    print(json.dumps(failure), flush=True)
    sys.exit(1)
